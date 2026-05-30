#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>

#include "../include/common.h"
#include "../include/sha256.h"

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

static void transfer_stream(int sock, uint64_t total, int bloc,
                             char *hash_out, uint64_t *msgs_out, double *timp_out) {
    uint8_t *data = (uint8_t*)malloc(bloc);
    if (!data) DIE("malloc");
    memset(data, 0xAB, bloc);

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint64_t trimis = 0, mesaje = 0;
    double t_start = now_sec();

    while (trimis < total) {
        int de_trimis = (int)MIN((uint64_t)bloc, total - trimis);
        sha256_update(&ctx, data, de_trimis);
        ssize_t sent = send(sock, data, de_trimis, 0);
        if (sent <= 0) { perror("send"); break; }
        trimis += (uint64_t)sent;
        mesaje++;
        uint64_t total_blocuri = total / bloc;
        if (total_blocuri == 0) total_blocuri = 1;
        if (mesaje % MAX(1, total_blocuri / 100) == 0)
            print_progress(trimis, total);
    }
    print_progress(trimis, total);
    printf("\n");

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    sha256_to_hex(hash, hash_out);
    *msgs_out = mesaje;
    *timp_out = now_sec() - t_start;
    free(data);
}

static void transfer_saw(int sock, uint64_t total, int bloc,
                          char *hash_out, uint64_t *msgs_out,
                          uint64_t *retr_out, double *timp_out) {
    uint8_t *data = (uint8_t*)malloc(bloc);
    if (!data) DIE("malloc");
    memset(data, 0xAB, bloc);

    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint64_t trimis = 0, mesaje = 0, retransmisii = 0;
    double t_start = now_sec();

    while (trimis < total) {
        int de_trimis = (int)MIN((uint64_t)bloc, total - trimis);
        sha256_update(&ctx, data, de_trimis);

        int confirmat = 0;
        for (int inc = 0; inc < SAW_MAX_RETRIES && !confirmat; inc++) {
            send(sock, data, de_trimis, 0);
            uint8_t ack = 0;
            ssize_t r = recv(sock, &ack, 1, MSG_WAITALL);
            if (r == 1 && ack == 0x06) confirmat = 1;
            else retransmisii++;
        }
        if (!confirmat) { fprintf(stderr, "\n[TCP-SAW] Esec\n"); break; }

        trimis += (uint64_t)de_trimis;
        mesaje++;
        uint64_t total_blocuri = total / bloc;
        if (total_blocuri == 0) total_blocuri = 1;
        if (mesaje % MAX(1, total_blocuri / 100) == 0)
            print_progress(trimis, total);
    }
    print_progress(trimis, total);
    printf("\n");

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    sha256_to_hex(hash, hash_out);
    *msgs_out = mesaje;
    *retr_out = retransmisii;
    *timp_out = now_sec() - t_start;
    free(data);
}

static void print_usage(const char *prog) {
    printf("Utilizare: %s [optiuni]\n\n", prog);
    printf("  -h HOST   Adresa server (implicit: 127.0.0.1)\n");
    printf("  -p PORT   Port          (implicit: %d)\n", PORT_TCP);
    printf("  -s BYTES  Dimensiune bloc (1-65535)\n");
    printf("  -d AMOUNT Date: 500m / 1g\n");
    printf("  -m MODE   Mod: stream / saw\n");
}

int main(int argc, char *argv[]) {
    char     host[128] = "127.0.0.1";
    int      port      = PORT_TCP;
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
                else { fprintf(stderr, "Foloseste: 500m sau 1g\n"); return 1; }
                break;
            case 'm':
                if (strcmp(optarg, "stream") == 0) mod = MODE_STREAM;
                else if (strcmp(optarg, "saw") == 0) mod = MODE_SAW;
                else { fprintf(stderr, "Mod: stream/saw\n"); return 1; }
                break;
            default: print_usage(argv[0]); return 1;
        }
    }

    printf("╔══════════════════════════════════╗\n");
    printf("║      CLIENT TCP — PCD HW1        ║\n");
    printf("╚══════════════════════════════════╝\n");
    printf("  Server : %s:%d\n", host, port);
    printf("  Bloc   : %d bytes\n", bloc);
    printf("  Total  : %.0f MB\n", (double)total / (1024.0*1024.0));
    printf("  Mod    : %s\n\n", mod == MODE_STREAM ? "Streaming" : "Stop-and-Wait");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) DIE("socket");

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        fprintf(stderr, "IP invalid: %s\n", host); return 1;
    }

    printf("  Conectare la %s:%d ...\n", host, port);
    if (connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) DIE("connect");
    printf("  Conectat!\n\n");

    uint64_t total_net = htobe64(total);
    send(sock, &total_net, sizeof(uint64_t), 0);

    char     hash_hex[65];
    uint64_t mesaje = 0, retransmisii = 0;
    double   timp   = 0.0;

    printf("  Transfer in curs...\n");
    if (mod == MODE_STREAM)
        transfer_stream(sock, total, bloc, hash_hex, &mesaje, &timp);
    else
        transfer_saw(sock, total, bloc, hash_hex, &mesaje, &retransmisii, &timp);

    uint8_t  srv_hash[32];
    char     srv_hash_hex[65];
    ssize_t  r = recv(sock, srv_hash, 32, MSG_WAITALL);
    if (r == 32) sha256_to_hex(srv_hash, srv_hash_hex);
    else strcpy(srv_hash_hex, "N/A");

    double mbps = (double)total * 8.0 / timp / 1e6;

    printf("\n========== [CLIENT TCP] Rezultate ==========\n");
    printf("  Protocol        : TCP\n");
    printf("  Mod             : %s\n", mod == MODE_STREAM ? "Streaming" : "Stop-and-Wait");
    printf("  Dimensiune bloc : %d bytes\n", bloc);
    printf("  Timp total      : %.4f secunde\n", timp);
    printf("  Mesaje trimise  : %llu\n", (unsigned long long)mesaje);
    printf("  Bytes trimisi   : %llu (%.2f MB)\n",
           (unsigned long long)total, (double)total / (1024.0*1024.0));
    printf("  Throughput      : %.2f Mbps\n", mbps);
    if (mod == MODE_SAW)
        printf("  Retransmisii    : %llu\n", (unsigned long long)retransmisii);
    printf("  SHA-256 client  : %s\n", hash_hex);
    printf("  SHA-256 server  : %s\n", srv_hash_hex);
    printf("  Integritate     : %s\n",
           strcmp(hash_hex, srv_hash_hex) == 0 ? "✓ MATCH — corect!" : "✗ DIFERIT — eroare!");
    printf("=============================================\n");

    close(sock);
    return 0;
}
