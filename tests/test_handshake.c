
#include "handshake.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

int main(void)
{
    EVP_PKEY *alice_private = NULL;
    EVP_PKEY *bob_private = NULL;

    unsigned char alice_public[X25519_PUBLIC_KEY_LEN];
    unsigned char bob_public[X25519_PUBLIC_KEY_LEN];

    unsigned char alice_secret[X25519_SHARED_SECRET_LEN];
    unsigned char bob_secret[X25519_SHARED_SECRET_LEN];

    unsigned char salt[HKDF_SALT_LEN] = {
        0x10, 0x20, 0x30, 0x40,
        0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0,
        0xD0, 0xE0, 0xF0, 0x11
    };

    unsigned char alice_aes_key[AES_KEY_LEN];
    unsigned char bob_aes_key[AES_KEY_LEN];

    const unsigned char context[] =
        "secure-inline-channel-v1";

    int result = 1;

    /* Generate key pairs */
    if (!handshake_generate_keypair(
            &alice_private, alice_public) ||
        !handshake_generate_keypair(
            &bob_private, bob_public)) {
        printf("[FAIL] X25519 key pair generation\n");
        goto cleanup;
    }

    printf("[PASS] X25519 key pair generation\n");

    /* Derive shared secrets */
    if (!handshake_derive_shared_secret(
            alice_private, bob_public, alice_secret) ||
        !handshake_derive_shared_secret(
            bob_private, alice_public, bob_secret)) {
        printf("[FAIL] Shared secret derivation\n");
        goto cleanup;
    }

    if (memcmp(alice_secret, bob_secret,
               X25519_SHARED_SECRET_LEN) != 0) {
        printf("[FAIL] Shared secrets do not match\n");
        goto cleanup;
    }

    printf("[PASS] X25519 shared secret agreement\n");

    /* Derive AES keys */
    if (!handshake_derive_aes_key(
            alice_secret, salt,
            context, sizeof(context) - 1,
            alice_aes_key) ||
        !handshake_derive_aes_key(
            bob_secret, salt,
            context, sizeof(context) - 1,
            bob_aes_key)) {
        printf("[FAIL] HKDF key derivation\n");
        goto cleanup;
    }

    if (memcmp(alice_aes_key, bob_aes_key,
               AES_KEY_LEN) != 0) {
        printf("[FAIL] Derived AES keys do not match\n");
        goto cleanup;
    }

    printf("[PASS] HKDF-SHA-256 AES key agreement\n");

    /* Ensure changing the context changes the derived key */
    {
        unsigned char different_key[AES_KEY_LEN];
        const unsigned char different_context[] =
            "different-context";

        if (!handshake_derive_aes_key(
                alice_secret, salt,
                different_context,
                sizeof(different_context) - 1,
                different_key)) {
            printf("[FAIL] HKDF context variation\n");
            goto cleanup;
        }

        if (memcmp(alice_aes_key, different_key,
                   AES_KEY_LEN) == 0) {
            printf("[FAIL] HKDF context did not change key\n");
            OPENSSL_cleanse(different_key, AES_KEY_LEN);
            goto cleanup;
        }

        OPENSSL_cleanse(different_key, AES_KEY_LEN);
    }

    printf("[PASS] HKDF context separation\n");

    result = 0;

cleanup:
    EVP_PKEY_free(alice_private);
    EVP_PKEY_free(bob_private);

    OPENSSL_cleanse(alice_secret, sizeof(alice_secret));
    OPENSSL_cleanse(bob_secret, sizeof(bob_secret));
    OPENSSL_cleanse(alice_aes_key, sizeof(alice_aes_key));
    OPENSSL_cleanse(bob_aes_key, sizeof(bob_aes_key));

    return result;
}
