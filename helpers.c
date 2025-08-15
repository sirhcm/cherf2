#include "helpers.h"

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <unistd.h>

#include <monocypher.h>
#include <braid.h>
#include <braid/fd.h>
#include <braid/tcp.h>
#include <braid/ck.h>
#include <braid/ch.h>

#include "config.h"
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

int read_key(uint8_t key[static 32], const char *fn) {
  FILE *f;
  char _path[] = KEYFILE_PATH, *path = _path, *dir;

  while ((dir = strsep(&path, ":"))) {
    char p[PATH_MAX];
    if (dir[0] == '~' && (dir[1] == '/' || dir[1] == 0)) {
      char *home;
      if (!(home = getenv("HOME"))) continue;
      snprintf(p, sizeof(p), "%s%s/%s", home, dir + 1, fn);
    } else snprintf(p, sizeof(p), "%s/%s", dir, fn);
    if ((f = fopen(p, "rb"))) goto success;
    if (errno != ENOENT) return -1;
  }

  errno = ENOENT;
  return -1;

success:
  if (fread(key, 1, 32, f) != 32) return -1;
  return fclose(f);
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

void gen_keys(const uint8_t s_sk[static 32], const uint8_t s_pk[static 32], const uint8_t r_pk[32],
                     uint8_t e_pk[static 32], uint8_t es[static 32], uint8_t ss[static 32]) {
  uint8_t e_sk[32], buf[96];
  // generate ephemeral key
  rand_buf(32, e_sk);
  crypto_x25519_public_key(e_pk, e_sk);

  // derive (es) shared secret
  crypto_x25519(buf, e_sk, r_pk);
  memcpy(buf + 32, e_pk, 32);
  memcpy(buf + 64, r_pk, 32);
  crypto_blake2b(es, 32, buf, 96);
  crypto_wipe(buf, 96);
  // derive (ss) shared secret
  crypto_x25519(buf, s_sk, r_pk);
  memcpy(buf + 32, es, 32);
  crypto_blake2b(ss, 32, buf, 64);
  crypto_wipe(buf, 64);
  crypto_wipe(e_sk, 32);
}

int punch(braid_t b, char daemon, int port, ConnectData *cd) {
  if (!daemon) {
    printf("connecting ");
    fflush(stdout);
  }
  for (int i = 0; i < 10; i++) {
    int fd;
    char addr[INET_ADDRSTRLEN];
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = port, .sin_addr.s_addr = htonl(INADDR_ANY) };

    if (!daemon) {
      printf(".");
      fflush(stdout);
    }
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) err(EX_OSERR, "socket");
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) err(EX_OSERR, "bind to port %d", port);
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &(struct linger){ .l_onoff = 1, .l_linger = 0 }, sizeof(struct linger)))
      err(EX_OSERR, "setsockopt SO_LINGER");

    snprintf(addr, sizeof(addr), "%d.%d.%d.%d", cd->addr & 0xFF, (cd->addr >> 8) & 0xFF, (cd->addr >> 16) & 0xFF, (cd->addr >> 24) & 0xFF);

    if (tcpdial(b, fd, addr, htons(cd->port)) >= 0) {
      if (!daemon) printf(" done\n");
      return fd;
    }
    if (!daemon) {
      printf("\bx");
      fflush(stdout);
    }
    close(fd);
    if (i < 9) ckusleep(b, 1000000);
  }
  if (!daemon) putchar('\n');
  return -1;
}

#define n2h(x) (((x) < 10) ? (x) + '0' : (x) - 10 + 'A')
char *key2hex(char dst[static 64], uint8_t key[static 32]) {
  for (unsigned int i = 0; i < 32; i++) {
    dst[2 * i] = n2h(key[i] >> 4);
    dst[2 * i + 1] = n2h(key[i] & 0xF);
  }
  return dst;
}

void splice(braid_t b, char daemon, int from, int to, ch_t ch) {
  uint8_t buf[65536];
  ssize_t n;
  cord_t c = (cord_t)chrecv(b, ch);
  chdestroy(ch);
  while ((n = fdread(b, from, buf, sizeof(buf))) > 0 && errno != EAGAIN)
    if (fdwrite(b, to, buf, n) <= 0 && errno != EAGAIN) break;
  if (daemon) syslog(LOG_NOTICE, "splice done: %m");
  else warn("splice done");
  close(from);
  close(to);
  cordhalt(b, c);
}

