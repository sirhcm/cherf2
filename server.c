#define _XOPEN_SOURCE 700
#include <arpa/inet.h>
#include <err.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <monocypher.h>
#include <braid.h>
#include <braid/io.h>
#include <braid/fd.h>
#include <braid/tcp.h>
#include <braid/ch.h>
#include <braid/ck.h>

#include "config.h"
#include "helpers.h"
#define HASH_KEYCMP(a, b, n) ((n) == 32 ? crypto_verify32((uint8_t *)(a), (uint8_t *)(b)) : -1)
#include "uthash.h"

struct target {
  uint8_t pk[32];
  struct ad {
    ConnectData cd;
    ch_t ch;
    struct ad *next;
  } *head;
  size_t n;
  UT_hash_handle hh;
};

static struct { uint16_t p; char *i; } flags = { 1235, "rendez" };
static braid_t b;
static int count = 0;
static uint8_t s_sk[32], s_pk[32];
static struct target *map = NULL;

static void keepalive(int fd, ch_t c) {
  uint8_t p;
  for (;;) {
    cksleep(b, KEEPALIVE_INTERVAL);
    if (cktimeout(b, (usize (*)())fdread, 1024, KEEPALIVE_TIMEOUT, 4, b, fd, &p, 1) != 1 || p != KEEPALIVE) {
      chclose(b, c);
      return;
    }
  }
}

static struct ad *pop_ad(struct target *t) {
  struct ad *a = t->head;
  t->head = a->next;
  return a;
}

static void handle(int fd) {
  char ip[INET_ADDRSTRLEN], keystr[65] = {0};
  uint8_t p[PACKET_MAX], es[32], ss[32], nonce[24] = {0};
  struct sockaddr_in sa;

  getpeername(fd, (struct sockaddr *)&sa, &(socklen_t){sizeof(sa)});
  inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip));

  if (recv_packet(b, fd, p)) {
    syslog(LOG_NOTICE, "[%-15s] request failed: recv: %m", ip);
    goto done;
  }

  if (HEAD(p)->type == ATTACH || HEAD(p)->type == ADVERTISE) {
    HandshakeData *data = DATA(p, HandshakeData);
    uint8_t buf[96];

    syslog(LOG_DEBUG, "[%-15s] request received", ip);

    // derive (es) shared secret
    crypto_x25519(buf, s_sk, data->e);
    memcpy(buf + 32, data->e, 32);
    memcpy(buf + 64, s_pk, 32);
    crypto_blake2b(es, sizeof(es), buf, 96);
    crypto_wipe(buf, 96);

    if (crypto_aead_unlock(data->s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, data->s, 32)) {
      syslog(LOG_NOTICE, "[%-15s] corrupted packet (ephemeral)", ip);
      goto done;
    }
    nonce[23]++;

    // derive (ss) shared secret
    crypto_x25519(buf, s_sk, data->s);
    memcpy(buf + 32, es, 32);
    crypto_blake2b(ss, sizeof(ss), buf, 64);
    crypto_wipe(es, 32);
    crypto_wipe(buf, 64);
  } else {
    syslog(LOG_NOTICE, "[%-15s] unexpected packet type", ip);
    goto done;
  }

  if (HEAD(p)->type == ATTACH) {
    struct target *t;
    AttachData *data = DATA(p, AttachData);

    if (crypto_aead_unlock(data->t, data->mac2, ss, nonce, NULL, 0, data->t, 32)) {
      syslog(LOG_NOTICE, "[%-15s] corrupted packet (static)", ip);
      goto done;
    }
    nonce[23]++;

    // TODO: check client public key

    syslog(LOG_INFO, "[%-15s] ATTACH: %s", ip, key2hex(keystr, data->hs.s));

    HASH_FIND(hh, map, data->t, 32, t);
    if (t == NULL) {
      syslog(LOG_NOTICE, "[%-15s] target not found: %s", ip, key2hex(keystr, data->t));
      HEAD(p)->type = ERROR;
      DATA(p, ErrorData)->code = ERROR_NOT_FOUND;
    } else {
      struct ad *a = pop_ad(t);
      HEAD(p)->type = CONNECT;
      memcpy(DATA(p, ConnectData), &a->cd, sizeof(ConnectData));

      if (chsend(b, a->ch, (usize)&(ConnectData){ sa.sin_addr.s_addr, sa.sin_port })) {
        syslog(LOG_ERR, "[%-15s] chsend failed while handling ATTACH: %m", ip);
        goto done;
      } else chclose(b, a->ch);
    }
  } else {
    struct timespec ts;
    struct target *t;
    struct ad *a;
    ch_t c;
    char ok;
    cord_t keepc;
    AdvertiseData *data = DATA(p, AdvertiseData);
    ConnectData *cd;

    clock_gettime(CLOCK_REALTIME, &ts);
    if (crypto_aead_unlock((uint8_t *)&data->ts_ms, data->mac2, ss, nonce, NULL, 0, (uint8_t *)&data->ts_ms, sizeof(data->ts_ms))) {
      syslog(LOG_NOTICE, "[%-15s] corrupted packet (static)", ip);
      goto done;
    }
    nonce[23]++;

    if (((data->ts_ms > ts2ms(ts)) ? data->ts_ms - ts2ms(ts) : ts2ms(ts) - data->ts_ms) > 1000) {
      syslog(LOG_NOTICE, "[%-15s] advertise too old", ip);
      HEAD(p)->type = ERROR;
      DATA(p, ErrorData)->code = ERROR_INVALID_TIMESTAMP;
      goto send;
    }

    // TODO: check advertiser public key

    syslog(LOG_INFO, "[%-15s] ADVERT: %s", ip, key2hex(keystr, data->hs.s));
    c = chopen();

    HASH_FIND(hh, map, data->hs.s, 32, t);
    if (t == NULL) {
      if ((t = calloc(1, sizeof(struct target))) == NULL) {
        syslog(LOG_ERR, "[%-15s] calloc failed while handling ADVERT: %m", ip);
        goto done;
      }

      memcpy(t->pk, data->hs.s, 32);

      HASH_ADD(hh, map, pk, 32, t);
    } else if (t->n >= MAX_ADVERTS) {
      syslog(LOG_WARNING, "[%-15s] too many adverts", ip);
      HEAD(p)->type = ERROR;
      DATA(p, ErrorData)->code = ERROR_TOO_MANY_ADVERTS;
      goto send;
    }

    if ((a = malloc(sizeof(struct ad))) == NULL) {
      syslog(LOG_ERR, "[%-15s] calloc failed while handling ADVERT: %m", ip);
      goto done;
    }

    a->cd.addr = sa.sin_addr.s_addr;
    a->cd.port = sa.sin_port;
    a->ch = c;
    a->next = t->head;
    t->head = a;
    t->n++;

    keepc = braidadd(b, keepalive, 65536, "keepalive", CORD_NORMAL, 2, fd, c);
    cd = (ConnectData *)chrecv(b, c, &ok);

    if (--t->n == 0) {
      HASH_DEL(map, t);
      free(t);
    }

    if (!ok) {
      syslog(LOG_NOTICE, "[%-15s] connection timed out", ip);
      goto done;
    } else cordhalt(b, keepc);

    HEAD(p)->type = CONNECT;
    memcpy(DATA(p, ConnectData), cd, sizeof(ConnectData));
  }
send:
  crypto_aead_lock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), data_sz(p));
  crypto_wipe(ss, 32);
  if (fdwrite(b, fd, &p, packet_sz(p)) != packet_sz(p))
    syslog(LOG_NOTICE, "[%-15s] request failed: send: %m", ip);
done:
  close(fd);
  count--;
}

static void run_server(int s) {
  char keystr[65] = {0};
  syslog(LOG_INFO, "server starting on port %d with public key %s", flags.p, key2hex(keystr, s_pk));

  for (;;) {
    int c;

    if ((c = tcpaccept(b, s)) < 0) syslog(LOG_NOTICE, "accept failed: %m");

    if (count >= MAX_CONNECTIONS) {
      syslog(LOG_WARNING, "too many connections, dropping");
      close(c);
      continue;
    }

    count++;
    braidadd(b, handle, 65536, "handle", CORD_NORMAL, 1, c);
  }
}

int server_main(int argc, char **argv) {
  int opt, s;

  while ((opt = getopt(argc, argv, "p:i:")) != -1)
    switch (opt) {
      case 'p':
        if (!(flags.p = atoi(optarg))) goto usage;
        break;
      case 'i': flags.i = optarg; break;
      default: goto usage;
    }

  if ((argc - optind) != 0) goto usage;

  if (read_key(s_sk, flags.i)) err(EX_NOINPUT, "failed to open static private key '%s'", flags.i);
  crypto_x25519_public_key(s_pk, s_sk);

  if ((s = tcplisten(NULL, flags.p)) < 0) err(EX_OSERR, "tcplisten on port %d", flags.p);

  b = braidinit();
  braidadd(b, iovisor, 65536, "iovisor", CORD_SYSTEM, 0);
  braidadd(b, run_server, 65536, "run_server", CORD_NORMAL, 1, s);
  braidstart(b);
  return -1;

usage:
  errx(EX_USAGE,
      "usage: server [options]\n"
      "options:\n"
      "  -h        show this help message\n"
      "  -p port   port to serve on (default: %d)\n"
      "  -i file   name of static private key file (default: %s)\n",
      flags.p, flags.i);
}

