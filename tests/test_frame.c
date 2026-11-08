#include "frame.h"

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

    assert(session_init(&device1, SESSION_DEVICE1,
                        shared_secret, salt) == 0);

    assert(session_init(&device2, SESSION_DEVICE2,
                        shared_secret, salt) == 0);

    const unsigned char message[] = "Hello from Device1 to Device2!";
    size_t message_len = sizeof(message) - 1;

    unsigned char frame[256];
    unsigned char decrypted[256];

    size_t frame_len = 0;
    size_t decrypted_len = 0;

    assert(frame_encrypt(
        &device1, message, message_len,
        frame, sizeof(frame), &frame_len) == 1);

    assert(frame_len == message_len + FRAME_OVERHEAD);

    assert(frame_decrypt(
        &device2, frame, frame_len,
        decrypted, sizeof(decrypted), &decrypted_len) == 1);

    assert(decrypted_len == message_len);
    assert(memcmp(message, decrypted, message_len) == 0);

    puts("[PASS] Frame encryption/decryption roundtrip");

    /* Tampered authentication tag must be rejected. */
    frame[frame_len - 1] ^= 0x01;

    assert(frame_decrypt(
        &device2, frame, frame_len,
        decrypted, sizeof(decrypted), &decrypted_len) == 0);

    puts("[PASS] Tampered tag rejected");

    /* Restore the frame and tamper with the nonce. */
    frame[frame_len - 1] ^= 0x01;
    frame[0] ^= 0x01;

    assert(frame_decrypt(
        &device2, frame, frame_len,
        decrypted, sizeof(decrypted), &decrypted_len) == 0);

    puts("[PASS] Tampered nonce rejected");

    /* Reject truncated frames. */
    assert(frame_decrypt(
        &device2, frame, FRAME_OVERHEAD - 1,
        decrypted, sizeof(decrypted), &decrypted_len) == 0);

    puts("[PASS] Truncated frame rejected");

    session_cleanup(&device1);
    session_cleanup(&device2);

    return 0;
}