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
int recv_packet(braid_t b, int fd, uint8_t p[static PACKET_MAX]);
int punch(braid_t b, int port, ConnectData *cd);

#endif

