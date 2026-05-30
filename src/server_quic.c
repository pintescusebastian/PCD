#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "msquic.h"
#include "../include/common.h"
#include "../include/sha256.h"

#define CERT_FILE  "server.cert"
#define KEY_FILE   "server.key"

typedef struct {
    SHA256_CTX  sha_ctx;
    uint64_t    bytes_primiti;
    uint64_t    mesaje_primite;
    int         mod_saw;
    int         primul_buffer;
    HQUIC       stream;
} Sesiune;

const QUIC_API_TABLE *MsQuic = NULL;

QUIC_STATUS QUIC_API StreamCallback(
    HQUIC Stream, void *Context, QUIC_STREAM_EVENT *Event)
{
    Sesiune *ses = (Sesiune*)Context;

    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
            const QUIC_BUFFER *buf = &Event->RECEIVE.Buffers[i];
            if (buf->Length == 0) continue;

            uint8_t  *data = buf->Buffer;
            uint32_t  len  = buf->Length;

            if (ses->primul_buffer) {
                ses->mod_saw       = (data[0] == 0x01);
                ses->primul_buffer = 0;
                data++; len--;
                printf("[QUIC] Mod detectat: %s\n",
                       ses->mod_saw ? "Stop-and-Wait" : "Streaming");
            }
            if (len == 0) continue;

            sha256_update(&ses->sha_ctx, data, len);
            ses->bytes_primiti  += len;
            ses->mesaje_primite++;

            if (ses->mod_saw) {
                uint8_t *ack = malloc(1);
                ack[0] = 0x06;
                QUIC_BUFFER *qbuf = malloc(sizeof(QUIC_BUFFER));
                qbuf->Buffer = ack; qbuf->Length = 1;
                MsQuic->StreamSend(Stream, qbuf, 1, QUIC_SEND_FLAG_NONE, qbuf);
            }
        }
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        {
            uint8_t hash[32];
            sha256_final(&ses->sha_ctx, hash);
            char hex[65];
            sha256_to_hex(hash, hex);

            printf("\n====== [SERVER QUIC] Statistici ======\n");
            printf("  Protocol        : QUIC (msquic)\n");
            printf("  Mod             : %s\n",
                   ses->mod_saw ? "Stop-and-Wait" : "Streaming");
            printf("  Mesaje primite  : %llu\n",
                   (unsigned long long)ses->mesaje_primite);
            printf("  Bytes primiti   : %llu (%.2f MB)\n",
                   (unsigned long long)ses->bytes_primiti,
                   (double)ses->bytes_primiti / (1024.0*1024.0));
            printf("  SHA-256         : %s\n", hex);
            printf("=====================================\n\n");

            uint8_t *hash_buf = malloc(32);
            memcpy(hash_buf, hash, 32);
            QUIC_BUFFER *qbuf = malloc(sizeof(QUIC_BUFFER));
            qbuf->Buffer = hash_buf; qbuf->Length = 32;
            MsQuic->StreamSend(Stream, qbuf, 1, QUIC_SEND_FLAG_FIN, qbuf);
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        free(Event->SEND_COMPLETE.ClientContext);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->StreamClose(Stream);
        free(ses);
        break;

    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ConnectionCallback(
    HQUIC Connection, void *Context, QUIC_CONNECTION_EVENT *Event)
{
    (void)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[QUIC] Client conectat!\n");
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        {
            Sesiune *ses = calloc(1, sizeof(Sesiune));
            sha256_init(&ses->sha_ctx);
            ses->primul_buffer = 1;
            ses->stream = Event->PEER_STREAM_STARTED.Stream;
            printf("[QUIC] Stream nou deschis\n");
            MsQuic->SetCallbackHandler(
                Event->PEER_STREAM_STARTED.Stream,
                (void*)StreamCallback, ses);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[QUIC] Conexiune inchisa\n");
        MsQuic->ConnectionClose(Connection);
        break;
    default: break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ListenerCallback(
    HQUIC Listener, void *Context, QUIC_LISTENER_EVENT *Event)
{
    (void)Listener;
    HQUIC config = (HQUIC)Context;
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        MsQuic->SetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            (void*)ConnectionCallback, NULL);
        return MsQuic->ConnectionSetConfiguration(
            Event->NEW_CONNECTION.Connection, config);
    }
    return QUIC_STATUS_SUCCESS;
}

static int genereaza_certificate(void) {
    FILE *f = fopen(CERT_FILE, "r");
    if (f) { fclose(f); return 0; }
    printf("[QUIC] Generez certificate TLS...\n");
    int ret = system(
        "openssl req -x509 -newkey rsa:2048 "
        "-keyout server.key -out server.cert "
        "-days 365 -nodes "
        "-subj '/CN=localhost' 2>/dev/null");
    if (ret != 0) { fprintf(stderr, "Eroare certificate!\n"); return -1; }
    printf("[QUIC] Certificate generate!\n");
    return 0;
}

int main(int argc, char *argv[]) {
    int port = PORT_QUIC;
    if (argc >= 2) port = atoi(argv[1]);

    printf("╔══════════════════════════════════════╗\n");
    printf("║   SERVER QUIC (msquic) — PCD HW1     ║\n");
    printf("╚══════════════════════════════════════╝\n");
    printf("Port: %d\n\n", port);

    if (genereaza_certificate() != 0) return 1;

    QUIC_STATUS status = MsQuicOpen2(&MsQuic);
    if (QUIC_FAILED(status)) { fprintf(stderr, "MsQuicOpen2 esuat\n"); return 1; }

    HQUIC registration = NULL;
    const QUIC_REGISTRATION_CONFIG reg_config = {
        "pcd_hw1_server", QUIC_EXECUTION_PROFILE_LOW_LATENCY
    };
    status = MsQuic->RegistrationOpen(&reg_config, &registration);
    if (QUIC_FAILED(status)) { fprintf(stderr, "RegistrationOpen esuat\n"); return 1; }

    HQUIC configuration = NULL;
    const QUIC_BUFFER alpn = { sizeof("pcd") - 1, (uint8_t*)"pcd" };

    QUIC_SETTINGS settings;
    memset(&settings, 0, sizeof(settings));
    settings.IdleTimeoutMs            = 60000;
    settings.IsSet.IdleTimeoutMs      = TRUE;
    settings.ServerResumptionLevel    = QUIC_SERVER_RESUME_AND_ZERORTT;
    settings.IsSet.ServerResumptionLevel = TRUE;
    settings.PeerUnidiStreamCount        = 100;
    settings.IsSet.PeerUnidiStreamCount  = TRUE;
    settings.PeerBidiStreamCount         = 100;
    settings.IsSet.PeerBidiStreamCount   = TRUE;

    status = MsQuic->ConfigurationOpen(registration, &alpn, 1,
                                        &settings, sizeof(settings),
                                        NULL, &configuration);
    if (QUIC_FAILED(status)) { fprintf(stderr, "ConfigurationOpen esuat\n"); return 1; }

    QUIC_CERTIFICATE_FILE cert_file = { KEY_FILE, CERT_FILE };
    QUIC_CREDENTIAL_CONFIG cred_config;
    memset(&cred_config, 0, sizeof(cred_config));
    cred_config.Type            = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred_config.Flags           = QUIC_CREDENTIAL_FLAG_NONE;
    cred_config.CertificateFile = &cert_file;

    status = MsQuic->ConfigurationLoadCredential(configuration, &cred_config);
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "ConfigurationLoadCredential esuat: 0x%x\n", status);
        return 1;
    }

    HQUIC listener = NULL;
    status = MsQuic->ListenerOpen(registration, ListenerCallback,
                                   configuration, &listener);
    if (QUIC_FAILED(status)) { fprintf(stderr, "ListenerOpen esuat\n"); return 1; }

    QUIC_ADDR addr;
    memset(&addr, 0, sizeof(addr));
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&addr, (uint16_t)port);

    status = MsQuic->ListenerStart(listener, &alpn, 1, &addr);
    if (QUIC_FAILED(status)) { fprintf(stderr, "ListenerStart esuat\n"); return 1; }

    printf("[QUIC] Server pornit pe portul %d\n", port);
    printf("[QUIC] Astept conexiuni... (Ctrl+C pentru stop)\n\n");

    while (1) sleep(1);

    MsQuic->ListenerClose(listener);
    MsQuic->ConfigurationClose(configuration);
    MsQuic->RegistrationClose(registration);
    MsQuicClose(MsQuic);
    return 0;
}
