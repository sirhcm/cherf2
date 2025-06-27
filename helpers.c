#include "helpers.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <libdill.h>

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

int recv_packet(int fd, uint8_t p[static PACKET_MAX], int64_t deadline) {
  size_t tot = 0;

  do {
    ssize_t rc;
    if ((rc = brecv(fd, p, (tot == 0) ? 1 : packet_sz(p) - tot, deadline)) < 0) return -1;
    if (rc == 0) {
      errno = ECONNRESET;
      return -1;
    }
    tot += (size_t)rc;
  } while (tot < packet_sz(p));
  return 0;
}

