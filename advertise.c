#define _POSIX_C_SOURCE 199309L
#include <arpa/inet.h>
#include <err.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <monocypher.h>
#include <braid.h>
#include <braid/io.h>
#include <braid/ck.h>
#include <braid/ch.h>
#include <braid/fd.h>
#include <braid/tcp.h>

#include "config.h"
#include "helpers.h"
#include "packet.h"

static struct { int n; char *i, *r; } flags = { 5, "static", "rendez.pub" };
static braid_t b;
static char *r_host, *r_port;
static uint8_t s_sk[32], s_pk[32], r_pk[32];

static void advertise(void);

static void keepalive(int fd, cord_t c) {
  uint8_t p = KEEPALIVE;
  for (;;) {
    cksleep(b, KEEPALIVE_INTERVAL);
    if (cktimeout(b, (usize (*)())fdwrite, 1024, KEEPALIVE_TIMEOUT, 4, b, fd, &p, 1) != 1 || p != KEEPALIVE) {
      cordhalt(b, c);
      braidadd(b, advertise, 65536, "advertise", CORD_NORMAL, 0);
      return;
    }
  }
}

static int retries = 0;
static void advertise(void) {
  uint8_t e_pk[32], es[32], ss[32], nonce[24] = {0}, p[PACKET_MAX];
  int fd, t;
  uint16_t port;
  struct timespec ts;
  struct sockaddr_in sa;
  cord_t keepc;

  gen_keys(s_sk, s_pk, r_pk, e_pk, es, ss);
  if ((fd = tcpdial(b, -1, r_host, atoi(r_port))) < 0) {
    syslog(LOG_ERR, "tcpdial failed: %m (retries: %d/%d)", retries, ADVERTISE_RETRIES);
    if (++retries > ADVERTISE_RETRIES) braidexit(b);
    else {
      cksleep(b, ADVERTISE_RETRY_DELAY);
      braidadd(b, advertise, 65536, "advertise", CORD_NORMAL, 0);
      return;
    }
  }
  retries = 0;

  if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &(struct linger){ .l_onoff = 1, .l_linger = 0 }, sizeof(struct linger))) {
    syslog(LOG_ERR, "setsockopt: %m");
    exit(-1);
  }

  // create message
  HEAD(p)->type = ADVERTISE;
  memcpy(DATA(p, HandshakeData)->e, e_pk, 32);
  memcpy(DATA(p, HandshakeData)->s, s_pk, 32);
  clock_gettime(CLOCK_REALTIME, &ts);
  DATA(p, AdvertiseData)->ts_ms = ts2ms(ts);

  crypto_aead_lock(DATA(p, HandshakeData)->s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, DATA(p, HandshakeData)->s, 32);
  crypto_wipe(es, 32);
  nonce[23]++;
  crypto_aead_lock((uint8_t *)&DATA(p, AdvertiseData)->ts_ms, DATA(p, AdvertiseData)->mac2, ss, nonce, NULL, 0,
                   (uint8_t *)&DATA(p, AdvertiseData)->ts_ms, sizeof(DATA(p, AdvertiseData)->ts_ms));
  nonce[23]++;

  // send ADVERT
  if (fdwrite(b, fd, &p, packet_sz(p)) != packet_sz(p)) {
    close(fd);
    syslog(LOG_WARNING, "send ADVERT failed: %m");
    goto done;
  }

  syslog(LOG_INFO, "ADVERT installed at rendez");

  keepc = braidadd(b, keepalive, 65536, "keepalive", CORD_NORMAL, 2, fd, braidcurr(b));

  // receive CONNECT or ERROR
  recv_packet(b, fd, p);

  cordhalt(b, keepc);

  if (HEAD(p)->type == ERROR) {
    if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ErrorData)) < 0) {
      syslog(LOG_WARNING, "corrupted packet from rendez");
      close(fd);
      goto done;
    }
    if (DATA(p, ErrorData)->code == ERROR_UNAUTHORIZED) syslog(LOG_WARNING, "ERROR: UNAUTHORIZED");
    else if (DATA(p, ErrorData)->code == ERROR_INVALID_TIMESTAMP) syslog(LOG_WARNING, "ERROR: INVALID TIMESTAMP");
    else if (DATA(p, ErrorData)->code == ERROR_TOO_MANY_ADVERTS) syslog(LOG_WARNING, "ERROR: TOO MANY ADVERTS");
    else syslog(LOG_WARNING, "ERROR: unknown error code %d", DATA(p, ErrorData)->code);
    close(fd);
    goto done;
  } else if (HEAD(p)->type != CONNECT) {
    syslog(LOG_WARNING, "expected CONNECT or ERROR packet");
    close(fd);
    goto done;
  }
  if (crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ConnectData)) < 0) {
    syslog(LOG_WARNING, "corrupted packet from rendez");
    close(fd);
    goto done;
  }
  crypto_wipe(ss, 32);

  if (getsockname(fd, (struct sockaddr *)&sa, &(socklen_t){sizeof(sa)})) {
    syslog(LOG_ERR, "getsockname: %m");
    exit(-1);
  }
  close(fd);

  if ((fd = punch(b, 1, sa.sin_port, DATA(p, ConnectData))) < 0) {
    syslog(LOG_WARNING, "punch failed");
    goto done;
  }
  if (fdread(b, fd, &port, 2) != 2) {
    syslog(LOG_WARNING, "read port from client failed");
    close(fd);
    goto done;
  }

  syslog(LOG_INFO, "client successfully holepunched, connecting to port %d\n", port);

  if ((t = tcpdial(b, -1, "localhost", port)) < 0) {
    syslog(LOG_WARNING, "tcpdial to localhost:%d for client failed", port);
    close(fd);
    goto done;
  }

  if (fdwrite(b, fd, &(char){1}, 1) != 1) {
    syslog(LOG_WARNING, "send ack to client failed");
    close(fd);
    close(t);
    goto done;
  }

  {
    cord_t c1, c2;
    ch_t ch1 = chcreate(), ch2 = chcreate();
    // TODO: should this be a separate process?
    c1 = braidadd(b, (void (*)())splice, 131072, "splice", CORD_NORMAL, 5, b, 1, fd, t, ch1);
    c2 = braidadd(b, (void (*)())splice, 131072, "splice", CORD_NORMAL, 5, b, 1, t, fd, ch2);
    chsend(b, ch1, (usize)c2);
    chsend(b, ch2, (usize)c1);
  }
  braidadd(b, advertise, 65536, "advertise", CORD_NORMAL, 0);

done:
  cksleep(b, ADVERTISE_RETRY_DELAY);
  braidadd(b, advertise, 65536, "advertise", CORD_NORMAL, 0);
}

int advertise_main(int argc, char **argv) {
  int opt;

  while ((opt = getopt(argc, argv, "n:i:r:")) != -1)
    switch (opt) {
      case 'n':
        if (!(flags.n = atoi(optarg))) goto usage;
        break;
      case 'i': flags.i = optarg; break;
      case 'r': flags.r = optarg; break;
      default: goto usage;
    }

  if ((argc - optind) != 1) goto usage;

  // load keys
  if (read_key(s_sk, flags.i)) err(EX_NOINPUT, "failed to open static private key '%s'", flags.i);
  crypto_x25519_public_key(s_pk, s_sk);
  if (read_key(r_pk, flags.r)) err(EX_NOINPUT, "failed to open rendez public key '%s'", flags.r);

  if (!(r_port = strchr(argv[optind], ':'))) goto usage;
  *r_port++ = 0;
  r_host = argv[optind];

  b = braidinit();

  braidadd(b, iovisor, 65536, "iovisor", CORD_SYSTEM, 0);

  for (int i = 0; i < flags.n; i++) braidadd(b, advertise, 65536, "advertise", CORD_NORMAL, 0);
  braidstart(b);
  return -1;

usage:
  errx(EX_USAGE,
      "usage: advertise [options] <rendez host>:<rendez port>\n\n"
      "options:\n"
      "  -h        show this help message\n"
      "  -n N      spawn N simultaneous advertisers (default: %d)\n"
      "  -i file   name of static private key file (default: %s)\n"
      "  -r file   name of rendez public key file (default: %s)\n",
      flags.n, flags.i, flags.r);
}

