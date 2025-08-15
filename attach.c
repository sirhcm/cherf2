#define _XOPEN_SOURCE 700
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

#include "config.h"
#include "helpers.h"
#include "packet.h"

static struct { char *i, *r; } flags = { "static", "rendez.pub" };
static braid_t b;
static char *r_host, *r_port;
static uint8_t s_sk[32], s_pk[32], r_pk[32];

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

  if ((fd = punch(b, 0, sa.sin_port, DATA(p, ConnectData))) < 0) err(EX_TEMPFAIL, "punch failed");
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
    c1 = braidadd(b, (void (*)())splice, 131072, "splice", CORD_NORMAL, 5, b, 0, fd, STDOUT_FILENO, ch1);
    c2 = braidadd(b, (void (*)())splice, 131072, "splice", CORD_NORMAL, 5, b, 0, STDIN_FILENO, fd, ch2);
    chsend(b, ch1, (usize)c2);
    chsend(b, ch2, (usize)c1);
  }
}

int attach_main(int argc, char **argv) {
  int opt;
  char *t_port;
  uint8_t t_pk[32];

  while ((opt = getopt(argc, argv, "i:r:")) != -1)
    switch (opt) {
      case 'i': flags.i = optarg;
      case 'r': flags.r = optarg;
      default: goto usage;
    }

  if ((argc - optind) != 2) goto usage;

  // load keys
  if (read_key(s_sk, flags.i)) err(EX_NOINPUT, "failed to open static private key '%s'", flags.i);
  crypto_x25519_public_key(s_pk, s_sk);
  if (read_key(r_pk, flags.r)) err(EX_NOINPUT, "failed to open rendez public key '%s'", flags.r);

  if (!(r_port = strchr(argv[optind], ':'))) goto usage;
  *r_port++ = 0;
  r_host = argv[optind];
  if (!(t_port = strchr(argv[optind + 1], ':'))) goto usage;
  *t_port++ = 0;
  if (read_key(t_pk, argv[optind + 1])) err(EX_NOINPUT, "target keyfile '%s' not found", argv[optind + 1]);

  b = braidinit();

  braidadd(b, iovisor, 65536, "iovisor", CORD_SYSTEM, 0);
  braidadd(b, (void (*)())attach, 65536, "attach", CORD_NORMAL, 2, t_pk, atoi(t_port));
  braidstart(b);

  return -1;

usage:
  errx(EX_USAGE,
      "usage: attach [options] <rendez host>:<rendez port> <remote name>:<remote port>\n"
      "options:\n"
      "  -h        show this help message\n"
      "  -i file   name of static private key file (default: %s)\n"
      "  -r file   name of rendez public key file (default: %s)\n",
      flags.i, flags.r);
}

