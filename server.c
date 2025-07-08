#include <sys/signal.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <monocypher.h>
#include <braid.h>
#include <braid/fd.h>
#include <braid/tcp.h>
#include <braid/ch.h>

#include "helpers.h"
#define HASH_KEYCMP(a, b, n) ((n) == 32 ? crypto_verify32((uint8_t *)(a), (uint8_t *)(b)) : -1)
#include "uthash.h"

#define MAX_CONN 5
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

static braid_t b;
static int count = 0;
static uint8_t s_sk[32]; // my static secret key
static uint8_t s_pk[32]; // my static public key

static struct advert *map = NULL;

typedef unsigned long long ull;

/*
static void hexdump(const uint8_t *buf, size_t len) {
  for (uint8_t *p = (uint8_t *)buf; p < buf + len; p++) {
    if ((p - buf) % 16 == 0) printf("\n%04lx: ", (unsigned long)(p - buf));
    printf("%02x ", *p);
  }
  printf("\n");
}
*/

static void handle(braid_t b, int fd) {
  uint8_t p[PACKET_MAX], es[32], ss[32], nonce[24] = {0};
  struct sockaddr_in sa;

  getpeername(fd, (struct sockaddr *)&sa, &(socklen_t){sizeof(sa)});

  if (braid_recv_packet(b, fd, p)) {
    warn("read from client");
    goto done;
  }

  if (HEAD(p)->type == ATTACH || HEAD(p)->type == ADVERTISE) {
    HandshakeData *data = DATA(p, HandshakeData);
    uint8_t buf[96];

    // derive (es) shared secret
    crypto_x25519(buf, s_sk, data->e);
    memcpy(buf + 32, data->e, 32);
    memcpy(buf + 64, s_pk, 32);
    crypto_blake2b(es, sizeof(es), buf, 96);
    crypto_wipe(buf, 96);

    if (crypto_aead_unlock(data->s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, data->s, 32)) {
      warnx("corrupted packet (s)");
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
    warnx("unexpected packet type");
    goto done;
  }

  if (HEAD(p)->type == ATTACH) {
    struct advert *a;
    AttachData *data = DATA(p, AttachData);

    if (crypto_aead_unlock(data->t, data->mac2, ss, nonce, NULL, 0, data->t, 32)) {
      warnx("corrupted packet (t)");
      goto done;
    }
    nonce[23]++;

    // TODO: check client public key
    HASH_FIND(hh, map, data->t, 32, a);
    if (a == NULL) {
      warnx("target not found");
      for (int i = 0; i < 32; i++) printf("%02x", data->t[i]);
      puts("");
      HEAD(p)->type = ERROR;
      DATA(p, ErrorData)->code = ERROR_NOT_FOUND;
    } else {
      HEAD(p)->type = CONNECT;
      memcpy(DATA(p, ConnectData), &a->ads[a->n - 1].cd, sizeof(ConnectData));

      if (chsend(b, a->ads[a->n - 1].ch, (usize)&(ConnectData){ sa.sin_addr.s_addr, sa.sin_port })) {
        warn("chsend failed");
        goto done;
      }
    }
  } else {
    struct timespec ts;
    struct advert *a;
    ch_t c;
    AdvertiseData *data = DATA(p, AdvertiseData);

    clock_gettime(CLOCK_REALTIME, &ts);
    if (crypto_aead_unlock((uint8_t *)&data->ts_ms, data->mac2, ss, nonce, NULL, 0, (uint8_t *)&data->ts_ms, sizeof(data->ts_ms))) {
      warnx("corrupted packet (timestamp)");
      goto done;
    }
    nonce[23]++;

    if (((data->ts_ms > ts2ms(ts)) ? data->ts_ms - ts2ms(ts) : ts2ms(ts) - data->ts_ms) > 1000) {
      warnx("advertise too old");
      HEAD(p)->type = ERROR;
      DATA(p, ErrorData)->code = ERROR_INVALID_TIMESTAMP;
      goto send;
    }

    // TODO: check advertiser public key

    printf("advertising from: ");
    for (int i = 0; i < 32; i++) printf("%02x", data->hs.s[i]);
    puts("");
    c = chcreate(b);

    HASH_FIND(hh, map, data->hs.s, 32, a);
    if (a == NULL) {
      if ((a = malloc(sizeof(struct advert))) == NULL) {
        warn("malloc failed");
        goto done;
      }

      memset(a, 0, sizeof(struct advert));
      memcpy(a->pk, data->hs.s, 32);

      a->n = 1;
      a->ads[0].cd.addr = sa.sin_addr.s_addr;
      a->ads[0].cd.port = sa.sin_port;
      a->ads[0].ch = c;
      HASH_ADD(hh, map, pk, 32, a);
    } else {
      if (a->n >= MAX_ADVERTS) {
        warnx("too many adverts");
        HEAD(p)->type = ERROR;
        DATA(p, ErrorData)->code = ERROR_TOO_MANY_ADVERTS;
        goto send;
      } else {
        a->n++;
        a->ads[a->n].cd.addr = sa.sin_addr.s_addr;
        a->ads[a->n].cd.port = sa.sin_port;
        a->ads[a->n].ch = c;
      }
    }

    HEAD(p)->type = CONNECT;
    memcpy(DATA(p, ConnectData), (ConnectData *)chrecv(b, c), sizeof(ConnectData));

    if (--a->n == 0) {
      HASH_DEL(map, a);
      free(a);
    }
  }
send:
  crypto_aead_lock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), data_sz(p));
  crypto_wipe(ss, 32);
  if (fdwrite(b, fd, &p, packet_sz(p)) != packet_sz(p)) warn("write to client");
done:
  close(fd);
  count--;
}

static void usage(const char *name) { errx(EX_USAGE, "usage: %s <port>", name); }
static void info(int sig) { (void)sig; braidinfo(b); }

static void run_server(braid_t b, int s) {
  for (;;) {
    int c;

    if ((c = tcpaccept(b, s)) < 0) { warn("accept failed"); }

    if (count >= MAX_CONN) {
      warnx("too many connections, dropping");
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

  sigaction(SIGQUIT, &(struct sigaction){ .sa_handler = info, .sa_flags = SA_RESTART }, NULL);

  if (argc != 2) usage(argv[0]);

  snprintf(p, sizeof(p), "%s/.cherf/rendez", getenv("HOME"));
  read_key(32, s_sk, p);
  crypto_x25519_public_key(s_pk, s_sk);

  if ((s = tcplisten(NULL, atoi(argv[1]))) < 0) err(EX_OSERR, "tcplisten on port %s", argv[1]);

  printf("server listening on port %d, running as pid=%d\n", atoi(argv[1]), getpid());

  b = braidinit();
  braidadd(b, fdvisor, 65536, "fdvisor", CORD_SYSTEM, 0);
  braidadd(b, chvisor, 65536, "chvisor", CORD_SYSTEM, 0);
  braidadd(b, run_server, 65536, "run_server", CORD_NORMAL, s);
  braidstart(b);
  return -1;
}

