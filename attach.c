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

static braid_t b;
static char *r_host, *r_port;
static uint8_t s_sk[32], s_pk[32], r_pk[32];

__attribute__((noreturn)) static void usage(const char *name) {
  errx(EX_USAGE, "usage: %s <rendez host> <rendez port> <remote name> <remote port>", name);
}

static void attach(const uint8_t t_pk[static 32], uint16_t port) {
  uint8_t e_pk[32], es[32], ss[32], nonce[24] = {0}, p[PACKET_MAX];
  int fd;
  struct sockaddr_in sa;
  char dummy;

  gen_keys(s_sk, s_pk, r_pk, e_pk, es, ss);
  if ((fd = tcpdial(b, -1, r_host, atoi(r_port))) < 0) err(EX_TEMPFAIL, "dial to %s:%s", r_host, r_port);
  if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &(struct linger){ .l_onoff = 1, .l_linger = 0 }, sizeof(struct linger)))
    err(EX_OSERR, "setsockopt SO_LINGER");

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

  if (getsockname(fd, (struct sockaddr *)&sa, &(socklen_t){sizeof(sa)})) err(EX_OSERR, "getsockname");
  close(fd);

  if ((fd = punch(b, sa.sin_port, DATA(p, ConnectData))) < 0) err(EX_TEMPFAIL, "punch failed");
  printf("connected to %s:%d\n", inet_ntoa(*(struct in_addr *)&DATA(p, ConnectData)->addr), ntohs(DATA(p, ConnectData)->port));
  if (fdwrite(b, fd, &port, 2) != 2) {
    warn("write port failed");
    close(fd);
    return;
  }
  if (fdread(b, fd, &dummy, 1) != 1) {
    warn("ack not received");
    close(fd);
    return;
  }

  {
    cord_t c1, c2;
    ch_t ch1 = chcreate(), ch2 = chcreate();
    c1 = braidadd(b, splice, 131072, "splice", CORD_NORMAL, 4, b, fd, STDOUT_FILENO, ch1);
    c2 = braidadd(b, splice, 131072, "splice", CORD_NORMAL, 4, b, STDIN_FILENO, fd, ch2);
    chsend(b, ch1, (usize)c2);
    chsend(b, ch2, (usize)c1);
  }
}

int attach_main(int argc, char **argv) {
  char p[PATH_MAX];
  uint8_t t_pk[32];

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
  read_key(sizeof(t_pk), t_pk, argv[3]);
  b = braidinit();

  braidadd(b, iovisor, 65536, "iovisor", CORD_SYSTEM, 0);
  braidadd(b, (void (*)())attach, 65536, "attach", CORD_NORMAL, 2, t_pk, atoi(argv[4]));
  braidstart(b);

  return -1;
}

