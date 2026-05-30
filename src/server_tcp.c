#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "../include/common.h"
#include "../include/sha256.h"

static void handle_client(int conn_fd, int use_saw) {
    uint64_t total_net = 0;
    recv(conn_fd, &total_net, sizeof(uint64_t), MSG_WAITALL);
    uint64_t total = be64toh(total_net);

    printf("[TCP] Astept %llu bytes (%.1f MB)\n",
           (unsigned long long)total,
           (double)total / (1024.0 * 1024.0));

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t *buf = (uint8_t*)malloc(64 * 1024);
    if (!buf) DIE("malloc");

    uint64_t primit = 0;
    uint64_t mesaje = 0;

    while (primit < total) {
        ssize_t n = recv(conn_fd, buf,
                         (size_t)MIN((uint64_t)(64*1024), total - primit),
                         MSG_WAITALL);
        if (n <= 0) break;
        sha256_update(&ctx, buf, (size_t)n);
        primit += (uint64_t)n;
        mesaje++;

        if (use_saw) {
            uint8_t ack = 0x06;
            send(conn_fd, &ack, 1, 0);
        }
    }

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    char hex[65];
    sha256_to_hex(hash, hex);

    send(conn_fd, hash, 32, 0);

    printf("\n====== [SERVER TCP] Statistici ======\n");
    printf("  Protocol        : TCP\n");
    printf("  Mod             : %s\n", use_saw ? "Stop-and-Wait" : "Streaming");
    printf("  Mesaje primite  : %llu\n", (unsigned long long)mesaje);
    printf("  Bytes primiti   : %llu (%.2f MB)\n",
           (unsigned long long)primit,
           (double)primit / (1024.0*1024.0));
    printf("  SHA-256 primit  : %s\n", hex);
    printf("=====================================\n\n");

    free(buf);
}

int main(int argc, char *argv[]) {
    int port = PORT_TCP;
    if (argc >= 2) port = atoi(argv[1]);

    printf("╔══════════════════════════════════╗\n");
    printf("║      SERVER TCP — PCD HW1        ║\n");
    printf("╚══════════════════════════════════╝\n");
    printf("Ascult pe portul %d (TCP)...\n\n", port);

    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) DIE("socket");

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons((uint16_t)port);
    srv.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv_fd, (struct sockaddr*)&srv, sizeof(srv)) < 0) DIE("bind");
    if (listen(srv_fd, 5) < 0) DIE("listen");

    while (1) {
        printf("[TCP] Astept conexiune...\n");
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int conn_fd = accept(srv_fd, (struct sockaddr*)&cli, &cli_len);
        if (conn_fd < 0) { perror("accept"); continue; }

        char cli_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli.sin_addr, cli_ip, sizeof(cli_ip));
        printf("[TCP] Conexiune de la %s\n", cli_ip);

        /* Primeste modul: primul byte dupa uint64_t total */
        /* Detectam SAW din optiunea socketului */
        handle_client(conn_fd, 0);
        close(conn_fd);
    }

    close(srv_fd);
    return 0;
}
