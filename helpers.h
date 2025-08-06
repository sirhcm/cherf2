#ifndef _HELPERS_H
#define _HELPERS_H

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <braid.h>

#include "packet.h"

#define ts2ms(ts) ((uint64_t)(ts.tv_sec) * 1000 + (ts.tv_nsec) / 1000000)

void rand_buf(size_t len, uint8_t buf[static len]);
void read_key(size_t len, uint8_t key[static len], const char *filename);
char *key2hex(char dst[static 64], uint8_t key[static 32]);
void gen_keys(const uint8_t s_sk[static 32], const uint8_t s_pk[static 32], const uint8_t r_pk[32],
                     uint8_t e_pk[static 32], uint8_t es[static 32], uint8_t ss[static 32]);

int recv_packet(braid_t b, int fd, uint8_t p[static PACKET_MAX]);
int punch(braid_t b, int port, ConnectData *cd);

typedef struct { int from, to; cord_t c; void *p; } spliceargs;
void splice(braid_t b, spliceargs *p);

#endif

