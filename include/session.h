#ifndef SESSION_H
#define SESSION_H

#include "crypto.h"
#include "handshake.h"

#include <stdint.h>

#define SESSION_NONCE_PREFIX_LEN 8

typedef enum {
    SESSION_DEVICE1 = 1,
    SESSION_DEVICE2 = 2
} SessionRole;

typedef struct {
    unsigned char tx_key[AES_KEY_LEN];
    unsigned char rx_key[AES_KEY_LEN];

    unsigned char nonce_prefix[SESSION_NONCE_PREFIX_LEN];
    uint64_t nonce_counter;

    int initialized;
} Session;

int session_init(
    Session *session,
    SessionRole role,
    const unsigned char shared_secret[X25519_SHARED_SECRET_LEN],
    const unsigned char salt[HKDF_SALT_LEN]
);

int session_generate_nonce(
    Session *session,
    unsigned char nonce[GCM_NONCE_LEN]
);

void session_cleanup(Session *session);

#endif