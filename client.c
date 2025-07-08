#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <monocypher.h>
#include <braid.h>
#include <braid/fd.h>
#include <braid/tcp.h>

#include "helpers.h"
#include "packet.h"

static char *r_host;
static char *r_port;
static uint8_t s_sk[32]; // my static secret key
static uint8_t s_pk[32]; // my static public key
static uint8_t r_pk[32]; // rendez static public key

__attribute__((noreturn)) static void usage(const char *name) {
  errx(EX_USAGE, "usage: %s <attach|advertise|ssh> ...", name);
}

static int tcp_open(const char *host, const char *port) {
  struct sockaddr addr;
  struct linger l = { .l_onoff = 1, .l_linger = 0 };
  socklen_t len;
  int s;

  resolve(&addr, &len, host, port);
  if ((s = socket(addr.sa_family, SOCK_STREAM, 0)) < 0) err(EX_OSERR, "socket");
  if (connect(s, &addr, len) < 0) err(EX_OSERR, "connect to %s:%s", host, port);
  if (setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) < 0) err(EX_OSERR, "setsockopt SO_LINGER");

  return s;
}

static int recv_packet(int fd, uint8_t p[static PACKET_MAX]) {
  size_t tot = 0;

  do {
    ssize_t rc;
    if ((rc = read(fd, p + tot, (tot == 0) ? 1 : packet_sz(p) - tot)) < 0) return -1;
    if (rc == 0) {
      errno = ECONNRESET;
      return -1;
    }
    tot += (size_t)rc;
  } while (tot < packet_sz(p));
  return 0;
}

static void gen_keys(uint8_t e_pk[static 32], uint8_t es[static 32], uint8_t ss[static 32]) {
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

struct spliceargs { int from, to; cord_t c; };

static void splice(braid_t b, struct spliceargs *p) {
  uint8_t buf[65536];
  ssize_t n;
  while ((n = fdread(b, p->from, buf, sizeof(buf))) > 0)
    if (fdwrite(b, p->to, buf, n) <= 0) break;
  close(p->from);
  close(p->to);
  cordhalt(b, p->c);
}

int attach(const uint8_t t_pk[static 32], const char *t_port) {
  uint8_t e_pk[32], es[32], ss[32], nonce[24] = {0}, p[PACKET_MAX];
  int fd;
  struct sockaddr_in sa;
  braid_t b;
  cord_t c1, c2;

  gen_keys(e_pk, es, ss);
  fd = tcp_open(r_host, r_port);

  // create message
  HEAD(p)->type = ATTACH;
  memcpy(DATA(p, HandshakeData)->e, e_pk, 32);
  memcpy(DATA(p, HandshakeData)->s, s_pk, 32);
  memcpy(DATA(p, AttachData)->t, t_pk, 32);

  crypto_aead_lock(DATA(p, HandshakeData)->s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, DATA(p, HandshakeData)->s, 32);
  crypto_wipe(es, 32);
  nonce[23]++;
  crypto_aead_lock(DATA(p, AttachData)->t, DATA(p, AttachData)->mac2, ss, nonce, NULL, 0, DATA(p, AttachData)->t, 32);
  nonce[23]++;

  // send ATTACH
  if (write(fd, &p, packet_sz(p)) != packet_sz(p)) err(EX_IOERR, "write to %s:%s", r_host, r_port);

  // receive CONNECT or ERROR
  recv_packet(fd, p);
  if (HEAD(p)->type == ERROR) {
    if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ErrorData)) < 0)
      errx(EX_PROTOCOL, "corrupted packet");
    if (DATA(p, ErrorData)->code == ERROR_UNAUTHORIZED) errx(EX_NOPERM, "unauthorized");
    if (DATA(p, ErrorData)->code == ERROR_NOT_FOUND) errx(EX_TEMPFAIL, "target not found");
    errx(EX_PROTOCOL, "unknown error code %d", DATA(p, ErrorData)->code);
  } else if (HEAD(p)->type != CONNECT) errx(EX_PROTOCOL, "expected CONNECT or ERROR packet");
  if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ConnectData)) < 0)
    errx(EX_PROTOCOL, "corrupted packet");
  crypto_wipe(ss, 32);

  if (getsockname(fd, &sa, &(socklen_t){sizeof(sa)})) err(EX_OSERR, "getsockname");
  close(fd);

  if ((fd = punch(sa.sin_port, DATA(p, ConnectData))) < 0) err(EX_TEMPFAIL, "punch failed");
  printf("connected to %s:%d\n", inet_ntoa(*(struct in_addr *)&DATA(p, ConnectData)->addr), ntohs(DATA(p, ConnectData)->port));
  write(fd, (uint16_t[]){atoi(t_port)}, 2);

  b = braidinit();
  braidadd(b, fdvisor, 65536, "fdvisor", CORD_SYSTEM, 0);
  c1 = braidadd(b, splice, 65536, "splice", CORD_NORMAL, 0);
  c2 = braidadd(b, splice, 65536, "splice", CORD_NORMAL, 0);
  *cordarg(c1) = (usize)&(struct spliceargs){fd, STDOUT_FILENO, c2};
  *cordarg(c2) = (usize)&(struct spliceargs){STDOUT_FILENO, fd, c1};
  braidstart(b);

  return 0;
}

void advertise(braid_t b) {
  uint8_t e_pk[32], es[32], ss[32], nonce[24] = {0}, p[PACKET_MAX];
  int fd, t;
  uint16_t port;
  struct linger l = { .l_onoff = 1, .l_linger = 0 };
  struct timespec ts;
  struct sockaddr_in sa;
  cord_t c1, c2;

  gen_keys(e_pk, es, ss);
  if ((fd = tcpdial(b, -1, r_host, atoi(r_port))) < 0) warnx("dial to %s:%s", r_host, r_port);
  if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l))) err(EX_OSERR, "setsockopt SO_LINGER");

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
  braid_recv_packet(b, fd, p);
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

  if ((fd = punch(sa.sin_port, DATA(p, ConnectData))) < 0) err(EX_TEMPFAIL, "punch failed");
  read(fd, &port, 2);
  printf("connecting to port %d\n", port);
  if ((t = tcpdial(b, -1, "localhost", port)) < 0) {
    warnx("dial to localhost:%d failed", port);
    close(fd);
    return;
  }

  write(t, "test", 4);

  // TODO: should this be a separate process?
  c1 = braidadd(b, splice, 65536, "splice", CORD_NORMAL, 0);
  c2 = braidadd(b, splice, 65536, "splice", CORD_NORMAL, 0);
  *cordarg(c1) = (usize)&(struct spliceargs){fd, t, c2};
  *cordarg(c2) = (usize)&(struct spliceargs){t, fd, c1};

  __attribute__((musttail)) return advertise(b);
}

int client_main(int argc, char **argv) {
  uint8_t t_pk[32];
  char p[PATH_MAX];

  if (argc < 2) usage(argv[0]);

  // load keys
  snprintf(p, sizeof(p), "%s/.cherf/static", getenv("HOME"));
  read_key(sizeof(s_sk), s_sk, p);
  snprintf(p, sizeof(p), "%s/.cherf/static.pub", getenv("HOME"));
  read_key(sizeof(s_pk), s_pk, p);
  snprintf(p, sizeof(p), "%s/.cherf/rendez.pub", getenv("HOME"));
  read_key(sizeof(r_pk), r_pk, p);

  if (strcmp(argv[1], "attach") == 0) {
    if (argc != 6) errx(EX_USAGE, "usage: %s attach <rendez host> <rendez port> <remote name> <remote port>", argv[0]);
    read_key(sizeof(t_pk), t_pk, argv[4]);
    r_host = argv[2];
    r_port = argv[3];
    return attach(t_pk, argv[5]);
  }
  if (strcmp(argv[1], "advertise") == 0) {
    braid_t b;

    if (argc != 4) errx(EX_USAGE, "usage: %s advertise <rendez host> <rendez port>", argv[0]);

    r_host = argv[2];
    r_port = argv[3];

    b = braidinit();
    braidadd(b, fdvisor, 65536, "fdvisor", CORD_SYSTEM, 0);

    for (int i = 0; i < 1; i++) braidadd(b, advertise, 65536, "advertise", CORD_NORMAL, 0);
    braidstart(b);

    return -1;
  }
  if (strcmp(argv[1], "ssh") == 0) errx(EX_SOFTWARE, "ssh not implemented yet");

  usage(argv[0]);
}
