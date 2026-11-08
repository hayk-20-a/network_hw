#include "session.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <string.h>

static const unsigned char DEVICE1_TO_DEVICE2[] =
    "network_hw:device1-to-device2";

static const unsigned char DEVICE2_TO_DEVICE1[] =
    "network_hw:device2-to-device1";

int session_init(
    Session *session,
    SessionRole role,
    const unsigned char shared_secret[X25519_SHARED_SECRET_LEN],
    const unsigned char salt[HKDF_SALT_LEN]
)
{
    if (session == NULL || shared_secret == NULL || salt == NULL) {
        return -1;
    }

    if (role != SESSION_DEVICE1 && role != SESSION_DEVICE2) {
        return -1;
    }

    memset(session, 0, sizeof(*session));

    const unsigned char *tx_context;
    size_t tx_context_len;
    const unsigned char *rx_context;
    size_t rx_context_len;

    if (role == SESSION_DEVICE1) {
        tx_context = DEVICE1_TO_DEVICE2;
        tx_context_len = sizeof(DEVICE1_TO_DEVICE2) - 1;

        rx_context = DEVICE2_TO_DEVICE1;
        rx_context_len = sizeof(DEVICE2_TO_DEVICE1) - 1;
    } else {
        tx_context = DEVICE2_TO_DEVICE1;
        tx_context_len = sizeof(DEVICE2_TO_DEVICE1) - 1;

        rx_context = DEVICE1_TO_DEVICE2;
        rx_context_len = sizeof(DEVICE1_TO_DEVICE2) - 1;
    }

    if (handshake_derive_aes_key(
            shared_secret,
            salt,
            tx_context,
            tx_context_len,
            session->tx_key) == 0) {
        session_cleanup(session);
        return -1;
    }

    if (handshake_derive_aes_key(
            shared_secret,
            salt,
            rx_context,
            rx_context_len,
            session->rx_key) == 0) {
        session_cleanup(session);
        return -1;
    }

    if (RAND_bytes(
            session->nonce_prefix,
            SESSION_NONCE_PREFIX_LEN) != 1) {
        session_cleanup(session);
        return -1;
    }

    session->nonce_counter = 0;
    session->initialized = 1;

    return 0;
}

int session_generate_nonce(
    Session *session,
    unsigned char nonce[GCM_NONCE_LEN]
)
{
    if (session == NULL || nonce == NULL || !session->initialized) {
        return -1;
    }

    if (session->nonce_counter > UINT32_MAX) {
        return -1;
    }

    memcpy(nonce, session->nonce_prefix, SESSION_NONCE_PREFIX_LEN);

    uint32_t counter = (uint32_t)session->nonce_counter;

    nonce[8]  = (unsigned char)(counter >> 24);
    nonce[9]  = (unsigned char)(counter >> 16);
    nonce[10] = (unsigned char)(counter >> 8);
    nonce[11] = (unsigned char)counter;

    session->nonce_counter++;

    return 0;
}

void session_cleanup(Session *session)
{
    if (session == NULL) {
        return;
    }

    OPENSSL_cleanse(session, sizeof(*session));
}