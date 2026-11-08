
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#define X25519_PUBLIC_KEY_LEN  32
#define X25519_SHARED_SECRET_LEN 32
#define HKDF_SALT_LEN          16

/*
 * Generate an X25519 key pair.
 *
 * private_key: receives the generated private key (EVP_PKEY).
 * public_key: receives the 32-byte public key.
 *
 * Caller must release private_key with EVP_PKEY_free().
 *
 * Returns 1 on success, 0 on failure.
 */
int handshake_generate_keypair(
    EVP_PKEY **private_key,
    unsigned char public_key[X25519_PUBLIC_KEY_LEN]
);

/*
 * Derive a shared secret using our private key and the peer's public key.
 *
 * Returns 1 on success, 0 on failure.
 */
int handshake_derive_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char peer_public_key[X25519_PUBLIC_KEY_LEN],
    unsigned char shared_secret[X25519_SHARED_SECRET_LEN]
);

/*
 * Derive an AES-256 key from the shared secret using HKDF-SHA-256.
 *
 * salt: 16-byte salt shared by both peers.
 * context: application-specific context string.
 *
 * Returns 1 on success, 0 on failure.
 */
int handshake_derive_aes_key(
    const unsigned char shared_secret[X25519_SHARED_SECRET_LEN],
    const unsigned char salt[HKDF_SALT_LEN],
    const unsigned char *context,
    size_t context_len,
    unsigned char aes_key[32]
);

#endif /* HANDSHAKE_H */
