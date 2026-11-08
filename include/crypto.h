
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AES_KEY_LEN      32
#define GCM_NONCE_LEN    12
#define GCM_TAG_LEN      16

/*
 * Encrypt plaintext using AES-256-GCM.
 *
 * Returns 1 on success, 0 on failure.
 */
int crypto_encrypt(
    const unsigned char key[AES_KEY_LEN],
    const unsigned char nonce[GCM_NONCE_LEN],
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    unsigned char tag[GCM_TAG_LEN]
);

/*
 * Decrypt ciphertext and authenticate its GCM tag.
 *
 * Returns 1 on successful authentication and decryption,
 * 0 on authentication failure or another error.
 */
int crypto_decrypt(
    const unsigned char key[AES_KEY_LEN],
    const unsigned char nonce[GCM_NONCE_LEN],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char tag[GCM_TAG_LEN],
    unsigned char *plaintext
);

#endif /* CRYPTO_H */
