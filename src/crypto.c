
#include "crypto.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

/*
 * Encrypt data using AES-256-GCM.
 *
 * The caller must provide output buffers large enough to hold
 * the ciphertext and the 16-byte authentication tag.
 */
int crypto_encrypt(
    const unsigned char key[AES_KEY_LEN],
    const unsigned char nonce[GCM_NONCE_LEN],
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    unsigned char tag[GCM_TAG_LEN])
{
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0;
    int final_len = 0;
    int success = 0;

    if (key == NULL || nonce == NULL ||
        ciphertext == NULL || tag == NULL) {
        return 0;
    }

    if (plaintext_len > INT_MAX) {
        return 0;
    }

    if (plaintext_len > 0 && plaintext == NULL) {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return 0;
    }

    if (EVP_EncryptInit_ex(
            ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_LEN, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(
            ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(
                ctx,
                ciphertext,
                &out_len,
                plaintext,
                (int)plaintext_len) != 1) {
            goto cleanup;
        }
    }

    if (EVP_EncryptFinal_ex(
            ctx, ciphertext + out_len, &final_len) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_LEN, tag) != 1) {
        goto cleanup;
    }

    success = 1;

cleanup:
    if (!success) {
        OPENSSL_cleanse(ciphertext, plaintext_len);
        OPENSSL_cleanse(tag, GCM_TAG_LEN);
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

/*
 * Decrypt data using AES-256-GCM.
 *
 * Plaintext is considered valid only after the authentication
 * tag has been successfully verified by EVP_DecryptFinal_ex().
 */
int crypto_decrypt(
    const unsigned char key[AES_KEY_LEN],
    const unsigned char nonce[GCM_NONCE_LEN],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char tag[GCM_TAG_LEN],
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0;
    int final_len = 0;
    int success = 0;

    if (key == NULL || nonce == NULL ||
        tag == NULL || plaintext == NULL) {
        return 0;
    }

    if (ciphertext_len > INT_MAX) {
        return 0;
    }

    if (ciphertext_len > 0 && ciphertext == NULL) {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return 0;
    }

    if (EVP_DecryptInit_ex(
            ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_LEN, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(
            ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(
                ctx,
                plaintext,
                &out_len,
                ciphertext,
                (int)ciphertext_len) != 1) {
            goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_LEN, (void *)tag) != 1) {
        goto cleanup;
    }

    /*
     * Authentication is verified here.
     * A failure means the ciphertext or tag is invalid.
     */
    if (EVP_DecryptFinal_ex(
            ctx, plaintext + out_len, &final_len) != 1) {
        goto cleanup;
    }

    success = 1;

cleanup:
    if (!success) {
        OPENSSL_cleanse(plaintext, ciphertext_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

