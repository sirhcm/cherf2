#ifndef _PACKET_H
#define _PACKET_H

#include <stdint.h>

#define HEAD(p) ((Header *)(p))
#define DATA(p, type) ((type *)((uint8_t *)(p) + sizeof(Header)))
#define PACKET_MAX (sizeof(Header) + sizeof(AttachData))
#define data_sz(p) (HEAD(p)->type == ATTACH ? sizeof(AttachData) : \
  HEAD(p)->type == ADVERTISE ? sizeof(AdvertiseData) : \
  HEAD(p)->type == CONNECT ? sizeof(ConnectData) : \
  HEAD(p)->type == ERROR ? sizeof(ErrorData) : 0)
#define packet_sz(p) (sizeof(Header) + data_sz(p))

enum {
  ATTACH,
  ADVERTISE,
  CONNECT,
  ERROR = 0xFF
};

enum {
  ERROR_UNAUTHORIZED,
  ERROR_NOT_FOUND,
  ERROR_INVALID_TIMESTAMP,
  ERROR_TOO_MANY_ADVERTS,
};

typedef struct __attribute__((packed)) {
  uint8_t type;
  uint8_t mac[16];
} Header;

typedef struct {
  uint8_t e[32]; // ephemeral public key (plaintext)
  uint8_t s[32]; // static public key    (ciphered: es)
} HandshakeData;

typedef struct __attribute__((packed)) {
  HandshakeData hs;
  uint8_t t[32]; // target public key    (ciphered: ss)
  uint8_t mac2[16];
} AttachData;

typedef struct __attribute__((packed)) {
  HandshakeData hs;
  uint64_t ts_ms;
  uint8_t mac2[16];
} AdvertiseData;

typedef struct __attribute__((packed)) {
  uint32_t addr; // ciphered: ss
  uint16_t port; // ciphered: ss
} ConnectData;

typedef struct {
  uint8_t code;  // error: ciphered: ss
} ErrorData;

#endif

