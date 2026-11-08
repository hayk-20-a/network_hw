
#include "crypto.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char key[AES_KEY_LEN] = {0};
    unsigned char nonce[GCM_NONCE_LEN] = {0};

    const unsigned char plaintext[] =
        "Secure inline communication using AES-256-GCM";

    size_t plaintext_len = sizeof(plaintext) - 1;

    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char recovered[sizeof(plaintext)];
    unsigned char tag[GCM_TAG_LEN];

    /* Test 1: Encryption */
    if (!crypto_encrypt(
            key,
            nonce,
            plaintext,
            plaintext_len,
            ciphertext,
            tag)) {
        printf("[FAIL] Encryption failed\n");
        return 1;
    }

    printf("[PASS] AES-256-GCM encryption\n");

    /* Test 2: Decryption */
    if (!crypto_decrypt(
            key,
            nonce,
            ciphertext,
            plaintext_len,
            tag,
            recovered)) {
        printf("[FAIL] Decryption failed\n");
        return 1;
    }

    if (memcmp(plaintext, recovered, plaintext_len) != 0) {
        printf("[FAIL] Recovered plaintext does not match\n");
        return 1;
    }

    printf("[PASS] AES-256-GCM decryption and plaintext comparison\n");

    /* Test 3: Tampering detection */
    ciphertext[0] ^= 0x01;

    if (crypto_decrypt(
            key,
            nonce,
            ciphertext,
            plaintext_len,
            tag,
            recovered)) {
        printf("[FAIL] Tampered ciphertext was accepted\n");
        return 1;
    }

    printf("[PASS] Authentication rejects tampered ciphertext\n");

    printf("\nAll crypto tests passed!\n");

    return 0;
}
