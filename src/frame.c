#include "frame.h"
#include "crypto.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <string.h>

int frame_encrypt(
    Session *session,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *frame,
    size_t frame_capacity,
    size_t *frame_len
)
{
    if (session == NULL || !session->initialized ||
        plaintext == NULL || frame == NULL || frame_len == NULL) {
        return 0;
    }

    if (plaintext_len > INT_MAX ||
        plaintext_len > SIZE_MAX - FRAME_OVERHEAD) {
        return 0;
    }

    size_t required_len = plaintext_len + FRAME_OVERHEAD;

    if (frame_capacity < required_len) {
        return 0;
    }

    unsigned char nonce[GCM_NONCE_LEN];
    unsigned char tag[GCM_TAG_LEN];

    if (session_generate_nonce(session, nonce) != 0) {
        return 0;
    }

    memcpy(frame, nonce, GCM_NONCE_LEN);

    unsigned char *ciphertext = frame + GCM_NONCE_LEN;

    if (!crypto_encrypt(
            session->tx_key,
            nonce,
            plaintext,
            plaintext_len,
            ciphertext,
            tag)) {
        OPENSSL_cleanse(frame, required_len);
        return 0;
    }

    memcpy(ciphertext + plaintext_len, tag, GCM_TAG_LEN);

    *frame_len = required_len;

    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(nonce, sizeof(nonce));

    return 1;
}

int frame_decrypt(
    const Session *session,
    const unsigned char *frame,
    size_t frame_len,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
)
{
    if (session == NULL || !session->initialized ||
        frame == NULL || plaintext == NULL || plaintext_len == NULL) {
        return 0;
    }

    if (frame_len < FRAME_OVERHEAD) {
        return 0;
    }

    size_t ciphertext_len = frame_len - FRAME_OVERHEAD;

    if (ciphertext_len > INT_MAX ||
        plaintext_capacity < ciphertext_len) {
        return 0;
    }

    const unsigned char *nonce = frame;
    const unsigned char *ciphertext = frame + GCM_NONCE_LEN;
    const unsigned char *tag = ciphertext + ciphertext_len;

    if (!crypto_decrypt(
            session->rx_key,
            nonce,
            ciphertext,
            ciphertext_len,
            tag,
            plaintext)) {
        OPENSSL_cleanse(plaintext, ciphertext_len);
        return 0;
    }

    *plaintext_len = ciphertext_len;

    return 1;
}