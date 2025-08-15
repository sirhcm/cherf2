// === GENERAL OPTIONS ===
// colon separated list specifying where to search for keys
#define KEYFILE_PATH ".:~/.cherf2"

// === RENDEZ SERVER OPTIONS ===
// maximum number of open connections for rendez server
#define MAX_CONNECTIONS 32
// maximum number of adverts per public key
#define MAX_ADVERTS 8

// === ADVERTISE OPTIONS ===
// how many times for advertiser to redial server
#define ADVERTISE_RETRIES 5
// how long to wait before redialing
#define ADVERTISE_RETRY_DELAY 30

// === EXTRA OPTIONS ===
// do not change the options below unless you know what you're doing!
// how often (in seconds) to send keepalive packets
#define KEEPALIVE_INTERVAL 15
// how long to wait for keepalive packets
#define KEEPALIVE_TIMEOUT 1
