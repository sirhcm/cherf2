#include <arpa/inet.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <monocypher.h>
#include <libdill.h>

#include "helpers.h"
#include "packet.h"

static uint8_t s_sk[32]; // my static secret key
static uint8_t s_pk[32]; // my static public key
static uint8_t r_pk[32]; // rendez static public key

__attribute__((noreturn))
static void usage(const char *name) {
  errx(EX_USAGE, "usage: %s <attach|advertise|ssh> ...", name);
}

static int tcp_open(const char *host, const char *port) {
  struct ipaddr addr;
  int s;

  if (ipaddr_remote(&addr, host, atoi(port), IPADDR_IPV4, -1)) errx(EX_OSERR, "could not resolve rendezvous host");
  if ((s = tcp_connect(&addr, -1)) < 0) err(EX_OSERR, "socket");

  return s;
}

int attach(const uint8_t t_pk[static 32], const char *r_addr, const char *r_port, const char *t_port) {
  int fd;
  uint8_t e_sk[32], e_pk[32], es[32], ss[32], buf[96], nonce[24] = {0}, p[PACKET_MAX];

  fd = tcp_open(r_addr, r_port);

  // generate ephemeral key
  rand_buf(32, e_sk);
  crypto_x25519_public_key(e_pk, e_sk);

  // derive (es) shared secret
  crypto_x25519(buf, e_sk, r_pk);
  memcpy(buf + 32, e_pk, 32);
  memcpy(buf + 64, s_pk, 32);
  crypto_blake2b(es, sizeof(es), buf, 96);
  crypto_wipe(buf, 32);
  // derive (ss) shared secret
  crypto_x25519(buf, s_sk, r_pk);
  memcpy(buf + 32, es, 32);
  crypto_blake2b(ss, sizeof(ss), buf, 64);
  crypto_wipe(e_sk, 32);

  // create message
  HEAD(p)->type = ATTACH;
  memcpy(DATA(p, AttachData)->hs.e, e_pk, 32);
  memcpy(DATA(p, AttachData)->hs.s, s_pk, 32);
  memcpy(DATA(p, AttachData)->t, t_pk, 32);

  crypto_aead_lock(DATA(p, AttachData)->hs.s, HEAD(p)->mac, es, nonce, &HEAD(p)->type, 1, DATA(p, AttachData)->hs.s, 32);
  crypto_wipe(es, 32);
  nonce[23]++;
  crypto_aead_lock(DATA(p, AttachData)->t, DATA(p, AttachData)->mac2, ss, nonce, NULL, 0, DATA(p, AttachData)->t, 32);
  nonce[23]++;

  // send ATTACH
  if (bsend(fd, &p, packet_sz(p), -1)) err(EX_IOERR, "write to %s:%s", r_addr, r_port);

  // receive CONNECT or ERROR
  recv_packet(fd, p, -1);
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

  printf("attempting to connect to %s:%d\n", inet_ntoa(*(struct in_addr *)&DATA(p, ConnectData)->addr), ntohs(DATA(p, ConnectData)->port));
  // TODO: actually connect!

  return 0;
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
    return attach(t_pk, argv[2], argv[3], argv[5]);
  }
  if (strcmp(argv[1], "advertise") == 0) errx(EX_SOFTWARE, "advertise not implemented yet");
  if (strcmp(argv[1], "ssh") == 0) errx(EX_SOFTWARE, "ssh not implemented yet");

  usage(argv[0]);
}
