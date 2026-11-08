#ifndef FRAME_H
#define FRAME_H

#include "session.h"

#include <stddef.h>
#include <stdint.h>

#define FRAME_OVERHEAD (GCM_NONCE_LEN + GCM_TAG_LEN)

/*
 * Frame layout:
 * nonce || ciphertext || authentication_tag
 *
 * Returns 1 on success, 0 on failure.
 */
int frame_encrypt(
    Session *session,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *frame,
    size_t frame_capacity,
    size_t *frame_len
);

int frame_decrypt(
    const Session *session,
    const unsigned char *frame,
    size_t frame_len,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
);

#endif