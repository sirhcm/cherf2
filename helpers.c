#include "helpers.h"

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <sys/socket.h>
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

void read_key(size_t len, uint8_t key[static len], const char *filename) {
  FILE *f;

  if ((f = fopen(filename, "rb")) == NULL) err(EX_NOINPUT, "fopen %s", filename);
  if (fread(key, 1, len, f) != len) err(EX_NOINPUT, "fread %s", filename);
  fclose(f);
}

int recv_packet(braid_t b, int fd, uint8_t p[static PACKET_MAX]) {
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

int punch(braid_t b, int port, ConnectData *cd) {
  printf("connecting ");
  fflush(stdout);
  for (int i = 0; i < 10; i++) {
    int fd;
    char addr[INET_ADDRSTRLEN];
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = port, .sin_addr.s_addr = htonl(INADDR_ANY) };

    printf(".");
    fflush(stdout);
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) err(EX_OSERR, "socket");
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) err(EX_OSERR, "bind to port %d", port);
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &(struct linger){ .l_onoff = 1, .l_linger = 0 }, sizeof(struct linger)))
      err(EX_OSERR, "setsockopt SO_LINGER");

    snprintf(addr, sizeof(addr), "%d.%d.%d.%d", cd->addr & 0xFF, (cd->addr >> 8) & 0xFF, (cd->addr >> 16) & 0xFF, (cd->addr >> 24) & 0xFF);

    if (tcpdial(b, fd, addr, htons(cd->port)) >= 0) {
      printf(" done\n");
      return fd;
    }
    printf("\bx");
    fflush(stdout);
    close(fd);
    if (i < 9) ckusleep(b, 1000000);
  }
  putchar('\n');
  return -1;
}

