#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>
#include <errno.h>

#include "../include/common.h"
#include "../include/sha256.h"

typedef struct __attribute__((packed)) {
    uint64_t seq_num;
    uint64_t total;
    uint16_t size;
    uint16_t flags;
} PktHeader;

#define FLAG_DATA  0x01
#define FLAG_FIN   0x02
#define FLAG_ACK   0x04
#define MAX_PKT (sizeof(PktHeader) + 65535)

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

static void send_stream(int sock, struct sockaddr_in *srv,
                         uint64_t total, int bloc,
                         char *hash_out, uint64_t *msgs_out, double *timp_out) {
    uint8_t *pkt_buf = (uint8_t*)malloc(MAX_PKT);
    if (!pkt_buf) DIE("malloc");
    uint8_t *payload = pkt_buf + sizeof(PktHeader);
    memset(payload, 0xAB, bloc);

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint64_t total_pkts = (total + bloc - 1) / bloc;
    uint64_t trimis = 0, seq = 0;
    double t_start = now_sec();

    while (trimis < total) {
        int de_trimis = (int)MIN((uint64_t)bloc, total - trimis);
        PktHeader *hdr = (PktHeader*)pkt_buf;
        hdr->seq_num = seq;
        hdr->total   = total_pkts;
        hdr->size    = (uint16_t)de_trimis;
        hdr->flags   = FLAG_DATA;

        sha256_update(&ctx, payload, de_trimis);
        sendto(sock, pkt_buf, sizeof(PktHeader) + de_trimis, 0,
               (struct sockaddr*)srv, sizeof(*srv));

        trimis += (uint64_t)de_trimis;
        seq++;
        if (seq % MAX(1, total_pkts / 100) == 0)
            print_progress(trimis, total);
    }
    print_progress(trimis, total);
    printf("\n");

    PktHeader *fin = (PktHeader*)pkt_buf;
    fin->seq_num = seq; fin->total = seq; fin->size = 0; fin->flags = FLAG_FIN;
    for (int i = 0; i < 3; i++) {
        sendto(sock, pkt_buf, sizeof(PktHeader), 0,
               (struct sockaddr*)srv, sizeof(*srv));
        usleep(10000);
    }

    double t_end = now_sec();

    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    recvfrom(sock, pkt_buf, 32, 0, NULL, NULL);

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    sha256_to_hex(hash, hash_out);
    *msgs_out = seq;
    *timp_out = t_end - t_start;
    free(pkt_buf);
}

static void send_saw(int sock, struct sockaddr_in *srv,
                      uint64_t total, int bloc,
                      char *hash_out, uint64_t *msgs_out,
                      uint64_t *retr_out, double *timp_out) {
    uint8_t *pkt_buf = (uint8_t*)malloc(MAX_PKT);
    uint8_t *ack_buf = (uint8_t*)malloc(sizeof(PktHeader));
    if (!pkt_buf || !ack_buf) DIE("malloc");
    uint8_t *payload = pkt_buf + sizeof(PktHeader);
    memset(payload, 0xAB, bloc);

    struct timeval tv;
    tv.tv_sec  = SAW_TIMEOUT_US / 1000000;
    tv.tv_usec = SAW_TIMEOUT_US % 1000000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint64_t total_pkts = (total + bloc - 1) / bloc;
    uint64_t trimis = 0, seq = 0, retransmisii = 0;
    int eroare = 0;
    double t_start = now_sec();

    while (trimis < total && !eroare) {
        int de_trimis = (int)MIN((uint64_t)bloc, total - trimis);
        PktHeader *hdr = (PktHeader*)pkt_buf;
        hdr->seq_num = seq;
        hdr->total   = total_pkts;
        hdr->size    = (uint16_t)de_trimis;
        hdr->flags   = FLAG_DATA | FLAG_ACK;

        sha256_update(&ctx, payload, de_trimis);

        int confirmat = 0;
        for (int inc = 0; inc < SAW_MAX_RETRIES && !confirmat; inc++) {
            sendto(sock, pkt_buf, sizeof(PktHeader) + de_trimis, 0,
                   (struct sockaddr*)srv, sizeof(*srv));
            ssize_t r = recvfrom(sock, ack_buf, sizeof(PktHeader), 0, NULL, NULL);
            if (r >= (ssize_t)sizeof(PktHeader)) {
                PktHeader *ack = (PktHeader*)ack_buf;
                if ((ack->flags & FLAG_ACK) && ack->seq_num == seq)
                    confirmat = 1;
                else retransmisii++;
            } else retransmisii++;
        }

        if (!confirmat) { fprintf(stderr, "\n[UDP-SAW] Esec la seq %llu\n",
                                  (unsigned long long)seq); eroare = 1; break; }

        trimis += (uint64_t)de_trimis;
        seq++;
        if (seq % MAX(1, total_pkts / 100) == 0)
            print_progress(trimis, total);
    }
    print_progress(trimis, total);
    printf("\n");

    PktHeader *fin = (PktHeader*)pkt_buf;
    fin->seq_num = seq; fin->total = seq; fin->size = 0;
    fin->flags = FLAG_FIN | FLAG_ACK;
    for (int i = 0; i < 3; i++) {
        sendto(sock, pkt_buf, sizeof(PktHeader), 0,
               (struct sockaddr*)srv, sizeof(*srv));
        usleep(10000);
    }

    double t_end = now_sec();

    struct timeval tv2 = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    recvfrom(sock, ack_buf, 32, 0, NULL, NULL);

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    sha256_to_hex(hash, hash_out);
    *msgs_out = seq;
    *retr_out = retransmisii;
    *timp_out = t_end - t_start;
    free(pkt_buf);
    free(ack_buf);
}

static void print_usage(const char *prog) {
    printf("Utilizare: %s [optiuni]\n\n", prog);
    printf("  -h HOST   Adresa server (implicit: 127.0.0.1)\n");
    printf("  -p PORT   Port          (implicit: %d)\n", PORT_UDP);
    printf("  -s BYTES  Dimensiune bloc (1-65535)\n");
    printf("  -d AMOUNT Date: 500m / 1g\n");
    printf("  -m MODE   Mod: stream / saw\n");
}

int main(int argc, char *argv[]) {
    char     host[128] = "127.0.0.1";
    int      port      = PORT_UDP;
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
    printf("║      CLIENT UDP — PCD HW1        ║\n");
    printf("╚══════════════════════════════════╝\n");
    printf("  Server : %s:%d\n", host, port);
    printf("  Bloc   : %d bytes\n", bloc);
    printf("  Total  : %.0f MB\n", (double)total / (1024.0*1024.0));
    printf("  Mod    : %s\n\n", mod == MODE_STREAM ? "Streaming" : "Stop-and-Wait");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) DIE("socket");

    int sndbuf = 8 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        fprintf(stderr, "IP invalid: %s\n", host); return 1;
    }

    char     hash_hex[65];
    uint64_t mesaje = 0, retransmisii = 0;
    double   timp   = 0.0;

    printf("  Transfer in curs...\n");
    if (mod == MODE_STREAM)
        send_stream(sock, &srv, total, bloc, hash_hex, &mesaje, &timp);
    else
        send_saw(sock, &srv, total, bloc, hash_hex, &mesaje, &retransmisii, &timp);

    double mbps = (double)total * 8.0 / timp / 1e6;

    printf("\n========== [CLIENT UDP] Rezultate ==========\n");
    printf("  Protocol        : UDP\n");
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
    printf("=============================================\n");

    close(sock);
    return 0;
}
