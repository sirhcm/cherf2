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
#include <braid/ck.h>

#include "helpers.h"
#include "packet.h"

static char *r_host;
static char *r_port;
static uint8_t s_sk[32]; // my static secret key
static uint8_t s_pk[32]; // my static public key
static uint8_t r_pk[32]; // rendez static public key

__attribute__((noreturn)) static void usage(const char *name) {
  errx(EX_USAGE, "usage: %s <rendez host> <rendez port> <remote name> <remote port>", name);
}

typedef struct { uint8_t t_pk[32]; uint16_t port; } attachargs;
static void attach(braid_t b, const attachargs *args) {
  uint8_t e_pk[32], es[32], ss[32], nonce[24] = {0}, p[PACKET_MAX];
  int fd;
  struct sockaddr_in sa;
  cord_t c1, c2;
  spliceargs *sargs1, *sargs2;

  gen_keys(s_sk, s_pk, r_pk, e_pk, es, ss);
  if ((fd = tcpdial(b, -1, r_host, atoi(r_port))) < 0) err(EX_TEMPFAIL, "dial to %s:%s", r_host, r_port);
  if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &(struct linger){ .l_onoff = 1, .l_linger = 0 }, sizeof(struct linger)))
    err(EX_OSERR, "setsockopt SO_LINGER");

  // create message
  HEAD(p)->type = ATTACH;
  memcpy(DATA(p, HandshakeData)->e, e_pk, 32);
  memcpy(DATA(p, HandshakeData)->s, s_pk, 32);
  memcpy(DATA(p, AttachData)->t, args->t_pk, 32);

  crypto_aead_lock(DATA(p, HandshakeData)->s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, DATA(p, HandshakeData)->s, 32);
  crypto_wipe(es, 32);
  nonce[23]++;
  crypto_aead_lock(DATA(p, AttachData)->t, DATA(p, AttachData)->mac2, ss, nonce, NULL, 0, DATA(p, AttachData)->t, 32);
  nonce[23]++;

  // send ATTACH
  if (write(fd, &p, packet_sz(p)) != packet_sz(p)) err(EX_IOERR, "write to %s:%s", r_host, r_port);

  // receive CONNECT or ERROR
  recv_packet(b, fd, p);
  if (HEAD(p)->type == ERROR) {
    if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ErrorData)) < 0)
      errx(EX_PROTOCOL, "corrupted packet");
    if (DATA(p, ErrorData)->code == ERROR_UNAUTHORIZED) errx(EX_NOPERM, "unauthorized");
    if (DATA(p, ErrorData)->code == ERROR_NOT_FOUND) errx(EX_TEMPFAIL, "target not found");
    errx(EX_PROTOCOL, "unknown error code %d", DATA(p, ErrorData)->code);
  } else if (HEAD(p)->type != CONNECT) errx(EX_PROTOCOL, "expected CONNECT or ERROR packet (got %d)", HEAD(p)->type);
  if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ConnectData)) < 0)
    errx(EX_PROTOCOL, "corrupted packet");
  crypto_wipe(ss, 32);

  if (getsockname(fd, &sa, &(socklen_t){sizeof(sa)})) err(EX_OSERR, "getsockname");
  close(fd);

  if ((fd = punch(b, sa.sin_port, DATA(p, ConnectData))) < 0) err(EX_TEMPFAIL, "punch failed");
  printf("connected to %s:%d\n", inet_ntoa(*(struct in_addr *)&DATA(p, ConnectData)->addr), ntohs(DATA(p, ConnectData)->port));
  if (write(fd, &args->port, 2) != 2) {
    warn("write port failed");
    close(fd);
    return;
  }

  c1 = braidadd(b, splice, 131072, "splice", CORD_NORMAL, 0);
  c2 = braidadd(b, splice, 131072, "splice", CORD_NORMAL, 0);

  sargs1 = malloc(sizeof(spliceargs));
  sargs2 = malloc(sizeof(spliceargs));
  sargs1->from = fd;
  sargs1->to = STDOUT_FILENO;
  sargs1->c = c2;
  sargs1->p = sargs2;
  sargs2->from = STDIN_FILENO;
  sargs2->to = fd;
  sargs2->c = c1;
  sargs2->p = sargs1;
  *cordarg(c1) = (usize)sargs1;
  *cordarg(c2) = (usize)sargs2;
}

int attach_main(int argc, char **argv) {
  char p[PATH_MAX];
  attachargs a;
  braid_t b = braidinit();

  // load keys
  snprintf(p, sizeof(p), "%s/.cherf2/static", getenv("HOME"));
  read_key(sizeof(s_sk), s_sk, p);
  snprintf(p, sizeof(p), "%s/.cherf2/static.pub", getenv("HOME"));
  read_key(sizeof(s_pk), s_pk, p);
  snprintf(p, sizeof(p), "%s/.cherf2/rendez.pub", getenv("HOME"));
  read_key(sizeof(r_pk), r_pk, p);


  if (argc != 5) usage(argv[0]);
  r_host = argv[1];
  r_port = argv[2];
  read_key(sizeof(a.t_pk), a.t_pk, argv[3]);
  a.port = (uint16_t)atoi(argv[4]);

  braidadd(b, iovisor, 65536, "iovisor", CORD_SYSTEM, 0);
  braidadd(b, attach, 65536, "attach", CORD_NORMAL, (usize)&a);
  braidstart(b);

  return -1;
}

