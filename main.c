#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <monocypher.h>

#include "helpers.h"

extern int client_main(int argc, char **argv);
#ifndef DISABLE_SERVER
extern int server_main(int argc, char **argv);
#endif

static void usage(const char *name) {
#ifdef DISABLE_SERVER
  errx(EX_USAGE, "usage: %s <client|keygen>", name);
#else
  errx(EX_USAGE, "usage: %s <client|server|keygen>", name);
#endif
}

static void keygen(const char *filename) {
  uint8_t sk[32], pk[32];
  char p[PATH_MAX];
  FILE *f;

  rand_buf(32, sk);
  crypto_x25519_public_key(pk, sk);

  if ((f = fopen(filename, "wb")) == NULL) err(EX_NOINPUT, "fopen %s", filename);
  if (fwrite(sk, 1, 32, f) != 32) err(EX_NOINPUT, "fwrite %s", filename);
  fclose(f);

  snprintf(p, sizeof(p), "%s.pub", filename);
  if ((f = fopen(p, "wb")) == NULL) err(EX_NOINPUT, "fopen %s", p);
  if (fwrite(pk, 1, 32, f) != 32) err(EX_NOINPUT, "fwrite %s", p);
  fclose(f);
}

int main(int argc, char **argv) {
  if (argc < 2) usage(argv[0]);
  if (strcmp(argv[1], "client") == 0) return client_main(argc - 1, argv + 1);
#ifndef DISABLE_SERVER
  if (strcmp(argv[1], "server") == 0) return server_main(argc - 1, argv + 1);
#endif
  if (strcmp(argv[1], "keygen") == 0) {
    if (argc != 3) errx(EX_USAGE, "usage: %s keygen <filename>", argv[0]);
    keygen(argv[2]);
    return 0;
  }
  usage(argv[0]);
}

