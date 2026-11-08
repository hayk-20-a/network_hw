
#include "handshake.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

int handshake_generate_keypair(
    EVP_PKEY **private_key,
    unsigned char public_key[X25519_PUBLIC_KEY_LEN])
{
    EVP_PKEY_CTX *ctx = NULL;
    size_t public_key_len = X25519_PUBLIC_KEY_LEN;
    int success = 0;

    if (private_key == NULL || public_key == NULL)
        return 0;

    *private_key = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL)
        goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(ctx, private_key) <= 0)
        goto cleanup;

    if (EVP_PKEY_get_raw_public_key(
            *private_key,
            public_key,
            &public_key_len) <= 0)
        goto cleanup;

    if (public_key_len != X25519_PUBLIC_KEY_LEN)
        goto cleanup;

    success = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);

    if (!success) {
        EVP_PKEY_free(*private_key);
        *private_key = NULL;
        OPENSSL_cleanse(public_key, X25519_PUBLIC_KEY_LEN);
    }

    return success;
}

int handshake_derive_shared_secret(
    EVP_PKEY *private_key,
    const unsigned char peer_public_key[X25519_PUBLIC_KEY_LEN],
    unsigned char shared_secret[X25519_SHARED_SECRET_LEN])
{
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len = X25519_SHARED_SECRET_LEN;
    int success = 0;

    if (private_key == NULL ||
        peer_public_key == NULL ||
        shared_secret == NULL)
        return 0;

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        X25519_PUBLIC_KEY_LEN);

    if (peer_key == NULL)
        goto cleanup;

    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (ctx == NULL)
        goto cleanup;

    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
        goto cleanup;

    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0)
        goto cleanup;

    if (secret_len != X25519_SHARED_SECRET_LEN)
        goto cleanup;

    success = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);

    if (!success)
        OPENSSL_cleanse(shared_secret, X25519_SHARED_SECRET_LEN);

    return success;
}

int handshake_derive_aes_key(
    const unsigned char shared_secret[X25519_SHARED_SECRET_LEN],
    const unsigned char salt[HKDF_SALT_LEN],
    const unsigned char *context,
    size_t context_len,
    unsigned char aes_key[32])
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6];
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    size_t key_len = 32;
    int success = 0;

    if (shared_secret == NULL ||
        salt == NULL ||
        context == NULL ||
        aes_key == NULL ||
        context_len > INT_MAX)
        return 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL)
        goto cleanup;

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL)
        goto cleanup;

    params[0] = OSSL_PARAM_construct_int(
    "mode", &mode);

    params[1] = OSSL_PARAM_construct_utf8_string(
    "digest", "SHA256", 0);

    params[2] = OSSL_PARAM_construct_octet_string(
    "key",
    (void *)shared_secret,
    X25519_SHARED_SECRET_LEN);

    params[3] = OSSL_PARAM_construct_octet_string(
    "salt",
    (void *)salt,
    HKDF_SALT_LEN);

    params[4] = OSSL_PARAM_construct_octet_string(
    "info",
    (void *)context,
    context_len);

    /* Required OSSL_PARAM terminator */
    params[5] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, aes_key, key_len, params) <= 0)
        goto cleanup;

    success = 1;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    if (!success)
        OPENSSL_cleanse(aes_key, key_len);

    return success;
}
