#include <sys/signal.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#include "helpers.h"
#define HASH_KEYCMP(a, b, n) ((n) == 32 ? crypto_verify32((uint8_t *)(a), (uint8_t *)(b)) : -1)
#include "uthash.h"

#define MAX_CONN 32
#define TIMEOUT_SEC 2
#define TS_EPS 1000
#define MAX_ADVERTS 8

#define EX_FATAL -1

struct advert {
  uint8_t pk[32];
  struct {
    ConnectData cd;
    ch_t ch;
  } ads[MAX_ADVERTS];
  size_t n;
  UT_hash_handle hh;
};

static int count = 0;
static uint8_t s_sk[32]; // my static secret key
static uint8_t s_pk[32]; // my static public key

static struct advert *map = NULL;

static void handle(braid_t b, int fd) {
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
    struct advert *a;
    AttachData *data = DATA(p, AttachData);

    if (crypto_aead_unlock(data->t, data->mac2, ss, nonce, NULL, 0, data->t, 32)) {
      syslog(LOG_NOTICE, "[%-15s] corrupted packet (static)", ip);
      goto done;
    }
    nonce[23]++;

    // TODO: check client public key

    syslog(LOG_INFO, "[%-15s] ATTACH: %s", ip, key2hex(keystr, data->hs.s));

    HASH_FIND(hh, map, data->t, 32, a);
    if (a == NULL) {
      syslog(LOG_NOTICE, "[%-15s] target not found: %s", ip, key2hex(keystr, data->t));
      HEAD(p)->type = ERROR;
      DATA(p, ErrorData)->code = ERROR_NOT_FOUND;
    } else {
      HEAD(p)->type = CONNECT;
      memcpy(DATA(p, ConnectData), &a->ads[a->n - 1].cd, sizeof(ConnectData));

      if (chsend(b, a->ads[a->n - 1].ch, (usize)&(ConnectData){ sa.sin_addr.s_addr, sa.sin_port })) {
        syslog(LOG_ERR, "[%-15s] chsend failed while handling ATTACH: %m", ip);
        goto done;
      }
      chdestroy(a->ads[a->n - 1].ch);
    }
  } else {
    struct timespec ts;
    struct advert *a;
    ch_t c;
    AdvertiseData *data = DATA(p, AdvertiseData);

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
    c = chcreate();

    HASH_FIND(hh, map, data->hs.s, 32, a);
    if (a == NULL) {
      if ((a = malloc(sizeof(struct advert))) == NULL) {
        syslog(LOG_ERR, "[%-15s] malloc failed while handling ADVERT: %m", ip);
        goto done;
      }

      memset(a, 0, sizeof(struct advert));
      memcpy(a->pk, data->hs.s, 32);

      a->ads[0].cd.addr = sa.sin_addr.s_addr;
      a->ads[0].cd.port = sa.sin_port;
      a->ads[0].ch = c;
      a->n = 1;
      HASH_ADD(hh, map, pk, 32, a);
    } else {
      if (a->n >= MAX_ADVERTS) {
        syslog(LOG_WARNING, "[%-15s] too many adverts", ip);
        HEAD(p)->type = ERROR;
        DATA(p, ErrorData)->code = ERROR_TOO_MANY_ADVERTS;
        goto send;
      } else {
        a->ads[a->n].cd.addr = sa.sin_addr.s_addr;
        a->ads[a->n].cd.port = sa.sin_port;
        a->ads[a->n].ch = c;
        a->n++;
      }
    }

    HEAD(p)->type = CONNECT;
    // TODO: tcp keepalive
    memcpy(DATA(p, ConnectData), (ConnectData *)chrecv(b, c), sizeof(ConnectData));

    if (--a->n == 0) {
      HASH_DEL(map, a);
      free(a);
    }
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

static int usage(const char *name) {
  fprintf(stderr, "usage: %s <port>", name);
  return 1;
}

static void run_server(braid_t b, int s) {
  for (;;) {
    int c;

    if ((c = tcpaccept(b, s)) < 0) syslog(LOG_NOTICE, "accept failed: %m");

    if (count >= MAX_CONN) {
      syslog(LOG_WARNING, "too many connections, dropping");
      close(c);
      continue;
    }

    count++;
    braidadd(b, handle, 65536, "handle", CORD_NORMAL, c);
  }
}

int server_main(int argc, char **argv) {
  char p[PATH_MAX];
  int s;
  braid_t b;

  if (argc != 2) return usage(argv[0]);

  snprintf(p, sizeof(p), "%s/.cherf2/rendez", getenv("HOME"));
  read_key(32, s_sk, p);
  crypto_x25519_public_key(s_pk, s_sk);

  if ((s = tcplisten(NULL, atoi(argv[1]))) < 0) {
    fprintf(stderr, "tcplisten on port %s: %s", argv[1], strerror(errno));
    return 1;
  }

  signal(SIGPIPE, SIG_IGN);

  b = braidinit();
  braidadd(b, iovisor, 65536, "iovisor", CORD_SYSTEM, 0);
  braidadd(b, run_server, 65536, "run_server", CORD_NORMAL, s);
  braidstart(b);
  return -1;
}

