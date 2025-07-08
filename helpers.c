#include "helpers.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <braid.h>
#include <braid/fd.h>
#include <braid/tcp.h>
#include <braid/ck.h>

#include "packet.h"

static int rand_fd = -1;
void rand_buf(size_t len, uint8_t buf[static len]) {
  size_t tot = 0;

  if (rand_fd == -1)
    if ((rand_fd = open("/dev/urandom", O_RDONLY)) < 0)
      err(EX_OSERR, "open /dev/urandom");

  while (tot < len) {
    ssize_t rc = read(rand_fd, buf + tot, len - tot);
    if (rc <= 0) err(EX_OSERR, "read /dev/urandom");
    tot += (size_t)rc;
  }
}

void resolve(struct sockaddr *sa, socklen_t *len, const char *host, const char *port) {
  struct addrinfo *res, hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV };

  if (getaddrinfo(host, port, &hints, &res)) {
    hints.ai_flags = 0;
    if (getaddrinfo(host, port, &hints, &res)) err(EX_OSERR, "getaddrinfo %s:%s", host, port);
  }

  memcpy(sa, res->ai_addr, res->ai_addrlen);
  *len = res->ai_addrlen;
  freeaddrinfo(res);
}

void read_key(size_t len, uint8_t key[static len], const char *filename) {
  FILE *f;

  if ((f = fopen(filename, "rb")) == NULL) err(EX_NOINPUT, "fopen %s", filename);
  if (fread(key, 1, len, f) != len) err(EX_NOINPUT, "fread %s", filename);
  fclose(f);
}

int braid_recv_packet(braid_t b, int fd, uint8_t p[static PACKET_MAX]) {
  size_t tot = 0;

  do {
    ssize_t rc;
    if ((rc = fdread(b, fd, p + tot, (tot == 0) ? 1 : packet_sz(p) - tot)) < 0) return -1;
    if (rc == 0) {
      errno = ECONNRESET;
      return -1;
    }
    tot += (size_t)rc;
  } while (tot < packet_sz(p));
  return 0;
}

#define TRIES 10

static int _bind(int port) {
  int fd;
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = port, .sin_addr.s_addr = htonl(INADDR_ANY) };
  struct linger l = { .l_onoff = 1, .l_linger = 0 };

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) err(EX_OSERR, "socket");
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) err(EX_OSERR, "bind to port %d", port);
  if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l))) err(EX_OSERR, "setsockopt SO_LINGER");
  return fd;
}

/*
int braidpunch(braid_t b, int port, ConnectData *cd) {
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = cd->port, .sin_addr.s_addr = cd->addr };
  for (int i = 0; i < TRIES; i++) {
    int fd = _bind(port);
    if (tcpdial(b, fd, (struct sockaddr *)&sa, sizeof(sa)) >= 0) return fd;
    else warn("connect to %s:%d", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
    close(fd);
    if (i < TRIES - 1) ckusleep(b, 1000000);
  }
  return -1;
}
*/

int punch(int port, ConnectData *cd) {
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = cd->port, .sin_addr.s_addr = cd->addr };
  printf("connecting");
  fflush(stdout);
  for (int i = 0; i < TRIES; i++) {
    int fd = _bind(port);
    printf(".");
    fflush(stdout);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) >= 0) { 
      printf(" connected\n");
      return fd;
    }
    printf("\bx");
    fflush(stdout);
    close(fd);
    if (i < TRIES - 1) usleep(1000000);
  }
  puts("");
  return -1;
}
