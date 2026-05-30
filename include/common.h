#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define PORT_TCP   9001
#define PORT_UDP   9002
#define PORT_QUIC  9003

#define DATA_500MB  (500ULL * 1024ULL * 1024ULL)
#define DATA_1GB   (1024ULL * 1024ULL * 1024ULL)

#define NUM_BLOCK_SIZES 5
static const int BLOCK_SIZES[NUM_BLOCK_SIZES] = {1, 500, 1000, 10000, 65535};

typedef enum {
    MODE_STREAM = 0,
    MODE_SAW    = 1
} TransferMode;

#define SAW_TIMEOUT_US   500000
#define SAW_MAX_RETRIES  10
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define DIE(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)
#endif
