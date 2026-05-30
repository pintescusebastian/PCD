#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>

#include "msquic.h"
#include "../include/common.h"
#include "../include/sha256.h"

typedef struct {
    int      bloc;
    uint64_t total;
    int      mod_saw;
    uint64_t bytes_trimisi;
    uint64_t mesaje_trimise;
    uint64_t retransmisii;
    double   timp_start;
    double   timp_end;
    char     hash_client[65];
    char     hash_server[65];
    volatile int conexiune_gata;
    volatile int terminat;
    volatile int ack_primit;
    HQUIC connection;
    HQUIC stream;
} TransferState;

const QUIC_API_TABLE *MsQuic = NULL;

static double now_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static void print_progress(uint64_t trimis, uint64_t total) {
    int pct    = (int)((double)trimis / (double)total * 100.0);
    int filled = pct / 5;
    printf("\r  [");
    for (int i = 0; i < 20; i++)
        printf(i < filled ? "█" : "░");
    printf("] %3d%%  %.1f / %.1f MB",
           pct,
           (double)trimis / (1024.0*1024.0),
           (double)total  / (1024.0*1024.0));
    fflush(stdout);
}

QUIC_STATUS QUIC_API StreamCallback(
    HQUIC Stream __attribute__((unused)),
    void *Context, QUIC_STREAM_EVENT *Event)
{
    TransferState *state = (TransferState*)Context;

    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (Event->SEND_COMPLETE.ClientContext)
            free(Event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
            const QUIC_BUFFER *buf = &Event->RECEIVE.Buffers[i];
            if (buf->Length == 1 && buf->Buffer[0] == 0x06)
                state->ack_primit = 1;
            else if (buf->Length == 32) {
                sha256_to_hex(buf->Buffer, state->hash_server);
                state->terminat = 1;
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        state->terminat = 1;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

static void *transfer_thread(void *arg) {
    TransferState *state = (TransferState*)arg;

    while (!state->conexiune_gata) usleep(1000);

    MsQuic->StreamOpen(state->connection, QUIC_STREAM_OPEN_FLAG_NONE,
                       StreamCallback, state, &state->stream);
    MsQuic->StreamStart(state->stream, QUIC_STREAM_START_FLAG_NONE);

    /* Trimite byte de mod: 0x01=SAW, 0x00=Stream */
    uint8_t *mod_buf = malloc(1);
    mod_buf[0] = state->mod_saw ? 0x01 : 0x00;
    QUIC_BUFFER *mod_qbuf = malloc(sizeof(QUIC_BUFFER));
    mod_qbuf->Buffer = mod_buf; mod_qbuf->Length = 1;
    MsQuic->StreamSend(state->stream, mod_qbuf, 1,
                       QUIC_SEND_FLAG_NONE, mod_qbuf);
    usleep(10000);

    uint8_t *data = malloc(state->bloc);
    if (!data) { state->terminat = 1; return NULL; }
    memset(data, 0xAB, state->bloc);

    SHA256_CTX sha_ctx;
    sha256_init(&sha_ctx);

    uint64_t trimis = 0, seq = 0;
    uint64_t total_pkts = (state->total + state->bloc - 1) / state->bloc;

    state->timp_start = now_sec();

    while (trimis < state->total) {
        int de_trimis = (int)MIN((uint64_t)state->bloc, state->total - trimis);
        sha256_update(&sha_ctx, data, de_trimis);

        uint8_t *buf_data = malloc(de_trimis);
        memcpy(buf_data, data, de_trimis);
        QUIC_BUFFER *quic_buf = malloc(sizeof(QUIC_BUFFER));
        quic_buf->Buffer = buf_data;
        quic_buf->Length = (uint32_t)de_trimis;

        MsQuic->StreamSend(state->stream, quic_buf, 1,
                           QUIC_SEND_FLAG_NONE, quic_buf);

        trimis += (uint64_t)de_trimis;
        seq++;
        state->bytes_trimisi  = trimis;
        state->mesaje_trimise = seq;

        if (seq % MAX(1, total_pkts / 100) == 0)
            print_progress(trimis, state->total);

        if (state->mod_saw) {
            state->ack_primit = 0;
            int retries = 0;
            while (!state->ack_primit && retries < SAW_MAX_RETRIES) {
                usleep(SAW_TIMEOUT_US / SAW_MAX_RETRIES);
                retries++;
            }
            if (!state->ack_primit) state->retransmisii++;
        }
    }

    print_progress(trimis, state->total);
    printf("\n");
    free(data);

    uint8_t hash[32];
    sha256_final(&sha_ctx, hash);
    sha256_to_hex(hash, state->hash_client);
    state->timp_end = now_sec();

    MsQuic->StreamShutdown(state->stream,
                            QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
    return NULL;
}

QUIC_STATUS QUIC_API ConnectionCallback(
    HQUIC Connection __attribute__((unused)),
    void *Context, QUIC_CONNECTION_EVENT *Event)
{
    TransferState *state = (TransferState*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[QUIC] Conexiune stabilita!\n\n");
        printf("  Transfer in curs...\n");
        state->conexiune_gata = 1;
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        state->terminat = 1;
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

static void print_usage(const char *prog) {
    printf("Utilizare: %s [optiuni]\n\n", prog);
    printf("  -h HOST   Adresa server (implicit: 127.0.0.1)\n");
    printf("  -p PORT   Port          (implicit: %d)\n", PORT_QUIC);
    printf("  -s BYTES  Dimensiune bloc (1-65535)\n");
    printf("  -d AMOUNT Date: 500m / 1g\n");
    printf("  -m MODE   Mod: stream / saw\n");
}

int main(int argc, char *argv[]) {
    char     host[128] = "127.0.0.1";
    int      port      = PORT_QUIC;
    int      bloc      = 1000;
    uint64_t total     = DATA_500MB;
    TransferMode mod   = MODE_STREAM;

    int opt;
    while ((opt = getopt(argc, argv, "h:p:s:d:m:")) != -1) {
        switch (opt) {
            case 'h': strncpy(host, optarg, sizeof(host)-1); break;
            case 'p': port = atoi(optarg); break;
            case 's':
                bloc = atoi(optarg);
                if (bloc < 1 || bloc > 65535) { fprintf(stderr, "Bloc: 1-65535!\n"); return 1; }
                break;
            case 'd':
                if (strcmp(optarg, "500m") == 0) total = DATA_500MB;
                else if (strcmp(optarg, "1g") == 0) total = DATA_1GB;
                else { fprintf(stderr, "Foloseste: 500m/1g\n"); return 1; }
                break;
            case 'm':
                if (strcmp(optarg, "stream") == 0) mod = MODE_STREAM;
                else if (strcmp(optarg, "saw") == 0) mod = MODE_SAW;
                else { fprintf(stderr, "Mod: stream/saw\n"); return 1; }
                break;
            default: print_usage(argv[0]); return 1;
        }
    }

    printf("╔══════════════════════════════════════╗\n");
    printf("║   CLIENT QUIC (msquic) — PCD HW1     ║\n");
    printf("╚══════════════════════════════════════╝\n");
    printf("  Server : %s:%d\n", host, port);
    printf("  Bloc   : %d bytes\n", bloc);
    printf("  Total  : %.0f MB\n", (double)total / (1024.0*1024.0));
    printf("  Mod    : %s\n\n", mod == MODE_STREAM ? "Streaming" : "Stop-and-Wait");

    TransferState state;
    memset(&state, 0, sizeof(state));
    state.bloc    = bloc;
    state.total   = total;
    state.mod_saw = (mod == MODE_SAW);
    strcpy(state.hash_server, "N/A");

    QUIC_STATUS status = MsQuicOpen2(&MsQuic);
    if (QUIC_FAILED(status)) { fprintf(stderr, "MsQuicOpen2 esuat\n"); return 1; }

    HQUIC registration = NULL;
    const QUIC_REGISTRATION_CONFIG reg_config = {
        "pcd_hw1_client", QUIC_EXECUTION_PROFILE_LOW_LATENCY
    };
    status = MsQuic->RegistrationOpen(&reg_config, &registration);
    if (QUIC_FAILED(status)) { fprintf(stderr, "RegistrationOpen esuat\n"); return 1; }

    HQUIC configuration = NULL;
    const QUIC_BUFFER alpn = { sizeof("pcd") - 1, (uint8_t*)"pcd" };

    QUIC_SETTINGS settings;
    memset(&settings, 0, sizeof(settings));
    settings.IdleTimeoutMs       = 60000;
    settings.IsSet.IdleTimeoutMs = TRUE;

    status = MsQuic->ConfigurationOpen(registration, &alpn, 1,
                                        &settings, sizeof(settings),
                                        NULL, &configuration);
    if (QUIC_FAILED(status)) { fprintf(stderr, "ConfigurationOpen esuat\n"); return 1; }

    QUIC_CREDENTIAL_CONFIG cred_config;
    memset(&cred_config, 0, sizeof(cred_config));
    cred_config.Type  = QUIC_CREDENTIAL_TYPE_NONE;
    cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT |
                        QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    status = MsQuic->ConfigurationLoadCredential(configuration, &cred_config);
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "ConfigurationLoadCredential esuat\n"); return 1;
    }

    status = MsQuic->ConnectionOpen(registration, ConnectionCallback,
                                     &state, &state.connection);
    if (QUIC_FAILED(status)) { fprintf(stderr, "ConnectionOpen esuat\n"); return 1; }

    pthread_t tid;
    pthread_create(&tid, NULL, transfer_thread, &state);

    printf("  Conectare la %s:%d...\n", host, port);
    status = MsQuic->ConnectionStart(state.connection, configuration,
                                      QUIC_ADDRESS_FAMILY_INET, host,
                                      (uint16_t)port);
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "ConnectionStart esuat: 0x%x\n", status); return 1;
    }

    while (!state.terminat) usleep(10000);
    pthread_join(tid, NULL);

    double timp = state.timp_end - state.timp_start;
    if (timp <= 0) timp = 0.001;
    double mbps = (double)total * 8.0 / timp / 1e6;

    printf("\n===== [CLIENT QUIC] Rezultate =====\n");
    printf("  Protocol        : QUIC (msquic)\n");
    printf("  Mod             : %s\n", mod == MODE_STREAM ? "Streaming" : "Stop-and-Wait");
    printf("  Dimensiune bloc : %d bytes\n", bloc);
    printf("  Timp total      : %.4f secunde\n", timp);
    printf("  Mesaje trimise  : %llu\n", (unsigned long long)state.mesaje_trimise);
    printf("  Bytes trimisi   : %llu (%.2f MB)\n",
           (unsigned long long)total, (double)total / (1024.0*1024.0));
    printf("  Throughput      : %.2f Mbps\n", mbps);
    if (mod == MODE_SAW)
        printf("  Retransmisii    : %llu\n", (unsigned long long)state.retransmisii);
    printf("  SHA-256 client  : %s\n", state.hash_client);
    printf("  SHA-256 server  : %s\n", state.hash_server);
    printf("  Integritate     : %s\n",
           strcmp(state.hash_client, state.hash_server) == 0
           ? "✓ MATCH — corect!" : "✗ DIFERIT — eroare!");
    printf("===================================\n");

    MsQuic->ConnectionClose(state.connection);
    MsQuic->ConfigurationClose(configuration);
    MsQuic->RegistrationClose(registration);
    MsQuicClose(MsQuic);
    return 0;
}
