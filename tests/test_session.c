#include "session.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char shared_secret[X25519_SHARED_SECRET_LEN];
    unsigned char salt[HKDF_SALT_LEN];

    memset(shared_secret, 0x42, sizeof(shared_secret));
    memset(salt, 0x19, sizeof(salt));

    Session device1;
    Session device2;

    assert(session_init(
        &device1,
        SESSION_DEVICE1,
        shared_secret,
        salt) == 0);

    assert(session_init(
        &device2,
        SESSION_DEVICE2,
        shared_secret,
        salt) == 0);

    /* Direction-specific keys must match across peers. */
    assert(memcmp(
        device1.tx_key,
        device2.rx_key,
        AES_KEY_LEN) == 0);

    assert(memcmp(
        device1.rx_key,
        device2.tx_key,
        AES_KEY_LEN) == 0);

    /* Keys for opposite directions must differ. */
    assert(memcmp(
        device1.tx_key,
        device1.rx_key,
        AES_KEY_LEN) != 0);

    unsigned char nonce1[GCM_NONCE_LEN];
    unsigned char nonce2[GCM_NONCE_LEN];
    unsigned char nonce3[GCM_NONCE_LEN];

    assert(session_generate_nonce(&device1, nonce1) == 0);
    assert(session_generate_nonce(&device1, nonce2) == 0);
    assert(session_generate_nonce(&device1, nonce3) == 0);

    /* Consecutive nonces must be unique. */
    assert(memcmp(nonce1, nonce2, GCM_NONCE_LEN) != 0);
    assert(memcmp(nonce2, nonce3, GCM_NONCE_LEN) != 0);
    assert(memcmp(nonce1, nonce3, GCM_NONCE_LEN) != 0);

    /* Verify the counter portion. */
    assert(nonce1[11] == 0);
    assert(nonce2[11] == 1);
    assert(nonce3[11] == 2);

    puts("[PASS] Directional session keys");
    puts("[PASS] Nonce uniqueness");
    puts("[PASS] Nonce counter increments");

    session_cleanup(&device1);
    session_cleanup(&device2);

    return 0;
}