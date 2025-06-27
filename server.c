#include <arpa/inet.h>
#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <monocypher.h>
#include <libdill.h>

#include "helpers.h"
#define HASH_KEYCMP(a, b, n) ((n) == 32 ? crypto_verify32((uint8_t *)(a), (uint8_t *)(b)) : -1)
#include "uthash.h"

#define MAX_CONN 5
#define TIMEOUT_SEC 2
#define TS_EPS 1000
#define MAX_ADVERTS 8

#ifdef MAP_HASSEMAPHORE
#define MMAP_FLAGS MAP_SHARED | MAP_ANONYMOUS | MAP_HASSEMAPHORE
#else
#define MMAP_FLAGS MAP_SHARED | MAP_ANONYMOUS
#endif
#define EX_FATAL -1

struct advert {
  uint8_t pk[32];
  struct {
    ConnectData cd;
    int ch;
  } ads[MAX_ADVERTS];
  size_t n;
  UT_hash_handle hh;
};

// parent
static int count = 0;
static uint8_t s_sk[32]; // my static secret key
static uint8_t s_pk[32]; // my static public key

// child
static struct advert *map = NULL;

static coroutine void handle(int fd, struct sockaddr_in *sa) {
  uint8_t p[PACKET_MAX], es[32], ss[32], nonce[24] = {0};

  if (recv_packet(fd, p, now() + TIMEOUT_SEC * 1000)) {
    warn("read from client");
    goto done;
  }

  if (HEAD(p)->type != ATTACH && HEAD(p)->type != ADVERTISE) {
    HandshakeData *data = DATA(p, HandshakeData);
    uint8_t buf[96];

    // derive (es) shared secret
    crypto_x25519(buf, s_sk, data->e);
    memcpy(buf + 32, data->e, 32);
    memcpy(buf + 64, s_pk, 32);
    crypto_blake2b(es, sizeof(es), buf, 96);
    crypto_wipe(buf, 96);

    if (crypto_aead_unlock(data->s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, data->s, 32)) { 
      warnx("corrupted packet");
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
      warnx("corrupted packet");
      goto done;
    }
    nonce[23]++;

    // TODO: check client public key
    HASH_FIND_PTR(map, data->t, a);
    if (a == NULL) {
      warnx("target not found");
      HEAD(p)->type = ERROR;
      DATA(p, ErrorData)->code = ERROR_NOT_FOUND;
    } else {
      HEAD(p)->type = CONNECT;
      memcpy(DATA(p, ConnectData), &a->ads[a->n - 1].cd, sizeof(ConnectData));

      if (chsend(a->ads[a->n - 1].ch, &(ConnectData){ sa->sin_addr.s_addr, sa->sin_port }, sizeof(ConnectData), -1)) {
        warn("chsend failed");
        goto done;
      }
    }
  } else {
    struct timespec ts;
    struct advert *a;
    int ch[2];
    AdvertiseData *data = DATA(p, AdvertiseData);

    clock_gettime(CLOCK_REALTIME, &ts);
    if (crypto_aead_unlock((uint8_t *)&data->ts_ms, data->mac2, ss, nonce, NULL, 0, (uint8_t *)&data->ts_ms, sizeof(data->ts_ms))) {
      warnx("corrupted packet");
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

    if (chmake(ch)) {
      warn("chmake failed");
      goto done;
    }

    HASH_FIND_PTR(map, data->hs.s, a);
    if (a == NULL) {
      if ((a = malloc(sizeof(struct advert))) == NULL) {
        warn("malloc failed");
        goto done;
      }

      memset(a, 0, sizeof(struct advert));
      memcpy(a->pk, data->hs.s, 32);

      a->n = 1;
      a->ads[0].cd.addr = sa->sin_addr.s_addr;
      a->ads[0].cd.port = sa->sin_port;
      a->ads[0].ch = ch[0];
    } else {
      if (a->n >= MAX_ADVERTS) {
        warnx("too many adverts");
        HEAD(p)->type = ERROR;
        DATA(p, ErrorData)->code = ERROR_TOO_MANY_ADVERTS;
        goto send;
      } else {
        a->n++;
        a->ads[a->n].cd.addr = sa->sin_addr.s_addr;
        a->ads[a->n].cd.port = sa->sin_port;
        a->ads[a->n].ch = ch[0];
      }
    }

    HEAD(p)->type = CONNECT;
    chrecv(ch[1], DATA(p, ConnectData), sizeof(ConnectData), -1);

    if (--a->n == 0) {
      HASH_DEL(map, a);
      free(a);
    }
  }
send:
  crypto_aead_lock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce, &HEAD(p)->type, 1, DATA(p, uint8_t), data_sz(p));
  crypto_wipe(ss, 32);
  if (bsend(fd, &p, packet_sz(p), now() + TIMEOUT_SEC * 1000)) warn("write to client");
done:
  tcp_close(fd, -1);
}

static void usage(const char *name) { errx(EX_USAGE, "usage: %s <port>", name); }

static void sigchld(int sig) {
  (void)sig;
  int status;
  while (waitpid(-1, &status, WNOHANG) > 0) {
    if (WEXITSTATUS(status) == EX_FATAL) errx(EX_OSERR, "child encountered fatal error, exiting");
    count--;
  }
}

int server_main(int argc, char **argv) {
  char p[PATH_MAX];
  struct ipaddr addr;
  int s;

  if (argc != 2) usage(argv[0]);

  snprintf(p, sizeof(p), "%s/.cherf/rendez", getenv("HOME"));
  read_key(32, s_sk, p);
  crypto_x25519_public_key(s_pk, s_sk);

  signal(SIGCHLD, sigchld);

  if (ipaddr_local(&addr, NULL, atoi(argv[1]), IPADDR_IPV4)) err(EX_OSERR, "could not resolve port");
  if ((s = tcp_listen(&addr, MAX_CONN)) < 0) err(EX_OSERR, "listen on socket failed");

  printf("server listening on port %d\n", atoi(argv[1]));

  while (1) {
    int c;
    struct ipaddr peer = {0};
    printf("waiting for connection...\n");

    if ((c = tcp_accept(s, &peer, -1)) < 0) { warn("accept failed"); }

    if (count >= MAX_CONN) {
      warnx("too many connections, dropping");
      tcp_close(c, -1);
      continue;
    }

    count++;
    go(handle(c, (struct sockaddr_in *)ipaddr_sockaddr(&peer)));
  }
}

