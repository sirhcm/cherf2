#include <arpa/inet.h>
#include <err.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <monocypher.h>
#include <braid.h>
#include <braid/io.h>
#include <braid/fd.h>
#include <braid/tcp.h>

#include "helpers.h"
#include "packet.h"

#ifdef __clang__
#define MUSTTAIL __attribute__((musttail))
#else
#define MUSTTAIL
#endif

static char *r_host;
static char *r_port;
static uint8_t s_sk[32]; // my static secret key
static uint8_t s_pk[32]; // my static public key
static uint8_t r_pk[32]; // rendez static public key

__attribute__((noreturn)) static void usage(const char *name) {
  errx(EX_USAGE, "usage: %s <rendez host> <rendez port>", name);
}

static void advertise(braid_t b) {
  uint8_t e_pk[32], es[32], ss[32], nonce[24] = {0}, p[PACKET_MAX];
  int fd, t;
  uint16_t port;
  struct timespec ts;
  struct sockaddr_in sa;
  cord_t c1, c2;
  spliceargs *sargs1, *sargs2;

  gen_keys(s_sk, s_pk, r_pk, e_pk, es, ss);
  if ((fd = tcpdial(b, -1, r_host, atoi(r_port))) < 0) err(EX_OSERR, "dial to %s:%s", r_host, r_port);
  if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &(struct linger){ .l_onoff = 1, .l_linger = 0 }, sizeof(struct linger)))
    err(EX_OSERR, "setsockopt SO_LINGER");

  // create message
  HEAD(p)->type = ADVERTISE;
  memcpy(DATA(p, HandshakeData)->e, e_pk, 32);
  memcpy(DATA(p, HandshakeData)->s, s_pk, 32);
  clock_gettime(CLOCK_REALTIME, &ts);
  DATA(p, AdvertiseData)->ts_ms = ts2ms(ts);

  crypto_aead_lock(DATA(p, HandshakeData)->s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, DATA(p, HandshakeData)->s, 32);
  crypto_wipe(es, 32);
  nonce[23]++;
  crypto_aead_lock(&DATA(p, AdvertiseData)->ts_ms, DATA(p, AdvertiseData)->mac2, ss, nonce, NULL, 0,
                   &DATA(p, AdvertiseData)->ts_ms, sizeof(DATA(p, AdvertiseData)->ts_ms));
  nonce[23]++;

  // send ADVERTISE
  if (fdwrite(b, fd, &p, packet_sz(p)) != packet_sz(p)) err(EX_IOERR, "write to %s:%s", r_host, r_port);
  printf("advertising with rendezvous %s:%s\n", r_host, r_port);

  // receive CONNECT or ERROR
  recv_packet(b, fd, p);
  if (HEAD(p)->type == ERROR) {
    if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ErrorData)) < 0)
      errx(EX_PROTOCOL, "corrupted packet");
    if (DATA(p, ErrorData)->code == ERROR_UNAUTHORIZED) errx(EX_NOPERM, "unauthorized");
    if (DATA(p, ErrorData)->code == ERROR_INVALID_TIMESTAMP) errx(EX_TEMPFAIL, "invalid timestamp");
    if (DATA(p, ErrorData)->code == ERROR_TOO_MANY_ADVERTS) errx(EX_TEMPFAIL, "too many adverts");
    errx(EX_PROTOCOL, "unknown error code %d", DATA(p, ErrorData)->code);
  } else if (HEAD(p)->type != CONNECT) errx(EX_PROTOCOL, "expected CONNECT or ERROR packet");
  if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ConnectData)) < 0)
    errx(EX_PROTOCOL, "corrupted packet");
  crypto_wipe(ss, 32);

  if (getsockname(fd, &sa, &(socklen_t){sizeof(sa)})) err(EX_OSERR, "getsockname");
  close(fd);

  if ((fd = punch(b, sa.sin_port, DATA(p, ConnectData))) < 0) err(EX_TEMPFAIL, "punch failed");
  if (fdread(b, fd, &port, 2) != 2) {
    warn("read port failed");
    close(fd);
    return;
  }

  printf("connecting to port %d\n", port);
  if ((t = tcpdial(b, -1, "localhost", port)) < 0) {
    warnx("dial to localhost:%d failed", port);
    close(fd);
    return;
  }

  // TODO: should this be a separate process?
  c1 = braidadd(b, splice, 131072, "splice", CORD_NORMAL, 0);
  c2 = braidadd(b, splice, 131072, "splice", CORD_NORMAL, 0);

  sargs1 = malloc(sizeof(spliceargs));
  sargs2 = malloc(sizeof(spliceargs));
  sargs1->from = fd;
  sargs1->to = t;
  sargs1->c = c2;
  sargs1->p = sargs2;
  sargs2->from = t;
  sargs2->to = fd;
  sargs2->c = c1;
  sargs2->p = sargs1;

  *cordarg(c1) = (usize)sargs1;
  *cordarg(c2) = (usize)sargs2;

  MUSTTAIL return advertise(b);
}

int advertise_main(int argc, char **argv) {
  char p[PATH_MAX];
  braid_t b = braidinit();

  if (argc != 3) usage(argv[0]);

  // load keys
  snprintf(p, sizeof(p), "%s/.cherf2/static", getenv("HOME"));
  read_key(sizeof(s_sk), s_sk, p);
  snprintf(p, sizeof(p), "%s/.cherf2/static.pub", getenv("HOME"));
  read_key(sizeof(s_pk), s_pk, p);
  snprintf(p, sizeof(p), "%s/.cherf2/rendez.pub", getenv("HOME"));
  read_key(sizeof(r_pk), r_pk, p);

  r_host = argv[1];
  r_port = argv[2];

  braidadd(b, iovisor, 65536, "iovisor", CORD_SYSTEM, 0);

  for (int i = 0; i < 1; i++) braidadd(b, advertise, 65536, "advertise", CORD_NORMAL, 0);
  braidstart(b);

  return -1;
}

