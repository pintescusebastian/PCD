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

static void send_ack(int sock, struct sockaddr_in *cli,
                     socklen_t cli_len, uint64_t seq) {
    PktHeader ack;
    memset(&ack, 0, sizeof(ack));
    ack.seq_num = seq;
    ack.flags   = FLAG_ACK;
    sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr*)cli, cli_len);
}

static void receive_stream(int sock, struct sockaddr_in *cli,
                            socklen_t cli_len, uint8_t *pkt_buf,
                            PktHeader *primul_hdr, uint8_t *primul_payload) {
    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint64_t bytes_primiti = 0, mesaje_primite = 0, pierdute = 0, next_seq = 0;

    if (primul_hdr->flags & FLAG_DATA) {
        sha256_update(&ctx, primul_payload, primul_hdr->size);
        bytes_primiti += primul_hdr->size;
        mesaje_primite++;
        next_seq = primul_hdr->seq_num + 1;
    }

    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        ssize_t n = recvfrom(sock, pkt_buf, MAX_PKT, 0,
                             (struct sockaddr*)cli, &cli_len);
        if (n < 0) { printf("[UDP] Timeout - transfer terminat\n"); break; }
        if ((size_t)n < sizeof(PktHeader)) continue;

        PktHeader *hdr   = (PktHeader*)pkt_buf;
        uint8_t  *payload = pkt_buf + sizeof(PktHeader);

        if (hdr->flags & FLAG_FIN) {
            send_ack(sock, cli, cli_len, hdr->seq_num);
            break;
        }
        if (!(hdr->flags & FLAG_DATA)) continue;

        if (hdr->seq_num > next_seq)
            pierdute += hdr->seq_num - next_seq;

        sha256_update(&ctx, payload, hdr->size);
        bytes_primiti += hdr->size;
        mesaje_primite++;
        next_seq = hdr->seq_num + 1;
    }

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    char hex[65];
    sha256_to_hex(hash, hex);
    sendto(sock, hash, 32, 0, (struct sockaddr*)cli, cli_len);

    printf("\n====== [SERVER UDP] Statistici (STREAM) ======\n");
    printf("  Protocol          : UDP\n");
    printf("  Mod               : Streaming\n");
    printf("  Mesaje primite    : %llu\n", (unsigned long long)mesaje_primite);
    printf("  Bytes primiti     : %llu (%.2f MB)\n",
           (unsigned long long)bytes_primiti,
           (double)bytes_primiti / (1024.0*1024.0));
    printf("  Pachete pierdute  : %llu\n", (unsigned long long)pierdute);
    printf("  SHA-256 primit    : %s\n", hex);
    printf("===============================================\n\n");
}

static void receive_saw(int sock, struct sockaddr_in *cli,
                         socklen_t cli_len, uint8_t *pkt_buf,
                         PktHeader *primul_hdr, uint8_t *primul_payload) {
    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint64_t bytes_primiti = 0, mesaje_primite = 0, expected_seq = 0;

    if (primul_hdr->flags & FLAG_DATA) {
        sha256_update(&ctx, primul_payload, primul_hdr->size);
        bytes_primiti += primul_hdr->size;
        mesaje_primite++;
        expected_seq = primul_hdr->seq_num + 1;
        send_ack(sock, cli, cli_len, primul_hdr->seq_num);
    }

    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        ssize_t n = recvfrom(sock, pkt_buf, MAX_PKT, 0,
                             (struct sockaddr*)cli, &cli_len);
        if (n < 0) { printf("[UDP-SAW] Timeout\n"); break; }
        if ((size_t)n < sizeof(PktHeader)) continue;

        PktHeader *hdr   = (PktHeader*)pkt_buf;
        uint8_t  *payload = pkt_buf + sizeof(PktHeader);

        if (hdr->flags & FLAG_FIN) {
            send_ack(sock, cli, cli_len, hdr->seq_num);
            break;
        }
        if (!(hdr->flags & FLAG_DATA)) continue;

        if (hdr->seq_num < expected_seq) {
            send_ack(sock, cli, cli_len, hdr->seq_num);
            continue;
        }

        sha256_update(&ctx, payload, hdr->size);
        bytes_primiti += hdr->size;
        mesaje_primite++;
        expected_seq = hdr->seq_num + 1;
        send_ack(sock, cli, cli_len, hdr->seq_num);
    }

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    char hex[65];
    sha256_to_hex(hash, hex);
    sendto(sock, hash, 32, 0, (struct sockaddr*)cli, cli_len);

    printf("\n====== [SERVER UDP] Statistici (SAW) ======\n");
    printf("  Protocol          : UDP\n");
    printf("  Mod               : Stop-and-Wait\n");
    printf("  Mesaje primite    : %llu\n", (unsigned long long)mesaje_primite);
    printf("  Bytes primiti     : %llu (%.2f MB)\n",
           (unsigned long long)bytes_primiti,
           (double)bytes_primiti / (1024.0*1024.0));
    printf("  SHA-256 primit    : %s\n", hex);
    printf("============================================\n\n");
}

int main(int argc, char *argv[]) {
    int port = PORT_UDP;
    if (argc >= 2) port = atoi(argv[1]);

    printf("╔══════════════════════════════════╗\n");
    printf("║      SERVER UDP — PCD HW1        ║\n");
    printf("╚══════════════════════════════════╝\n");
    printf("Ascult pe portul %d (UDP)...\n\n", port);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) DIE("socket");

    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons((uint16_t)port);
    srv.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) DIE("bind");

    uint8_t *pkt_buf = (uint8_t*)malloc(MAX_PKT);
    if (!pkt_buf) DIE("malloc");

    while (1) {
        printf("[UDP] Astept primul pachet...\n");

        struct timeval tv = {0, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);

        ssize_t n = recvfrom(sock, pkt_buf, MAX_PKT, 0,
                             (struct sockaddr*)&cli, &cli_len);
        if (n < (ssize_t)sizeof(PktHeader)) continue;

        PktHeader *hdr   = (PktHeader*)pkt_buf;
        uint8_t  *payload = pkt_buf + sizeof(PktHeader);

        /* Ignora pachetele FIN ca sesiune noua */
        if (hdr->flags & FLAG_FIN) continue;

        char cli_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli.sin_addr, cli_ip, sizeof(cli_ip));
        printf("[UDP] Sesiune noua de la %s:%d\n", cli_ip, ntohs(cli.sin_port));

        int use_saw = (hdr->flags & FLAG_ACK) != 0;
        printf("[UDP] Mod: %s\n", use_saw ? "Stop-and-Wait" : "Streaming");

        if (use_saw)
            receive_saw(sock, &cli, cli_len, pkt_buf, hdr, payload);
        else
            receive_stream(sock, &cli, cli_len, pkt_buf, hdr, payload);
    }

    free(pkt_buf);
    close(sock);
    return 0;
}
