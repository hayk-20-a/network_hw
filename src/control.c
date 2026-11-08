#include "control.h"
#include "handshake.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>

#define CONTROL_PUBLIC_KEY_LEN X25519_PUBLIC_KEY_LEN
#define CONTROL_INIT_MSG_LEN (CONTROL_PUBLIC_KEY_LEN + HKDF_SALT_LEN)

static int send_all(int fd, const unsigned char *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t result = send(fd, buffer + sent, length - sent, 0);

        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (result == 0) {
            return -1;
        }

        sent += (size_t)result;
    }

    return 0;
}

static int recv_all(int fd, unsigned char *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t result = recv(fd, buffer + received, length - received, 0);

        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (result == 0) {
            return -1;
        }

        received += (size_t)result;
    }

    return 0;
}

int control_handshake(int socket_fd, SessionRole role, Session *session)
{
    if (session == NULL ||
        (role != SESSION_DEVICE1 && role != SESSION_DEVICE2)) {
        return -1;
    }

    EVP_PKEY *private_key = NULL;

    unsigned char public_key[CONTROL_PUBLIC_KEY_LEN] = {0};
    unsigned char peer_public_key[CONTROL_PUBLIC_KEY_LEN] = {0};
    unsigned char salt[HKDF_SALT_LEN] = {0};
    unsigned char shared_secret[X25519_SHARED_SECRET_LEN] = {0};
    unsigned char init_message[CONTROL_INIT_MSG_LEN] = {0};

    int result = -1;

    if (handshake_generate_keypair(&private_key, public_key) != 1) {
        goto cleanup;
    }

    if (role == SESSION_DEVICE1) {
        if (RAND_bytes(salt, sizeof(salt)) != 1) {
            goto cleanup;
        }

        /* Device1 sends public key and salt first. */
        for (size_t i = 0; i < CONTROL_PUBLIC_KEY_LEN; i++) {
            init_message[i] = public_key[i];
        }

        for (size_t i = 0; i < HKDF_SALT_LEN; i++) {
            init_message[CONTROL_PUBLIC_KEY_LEN + i] = salt[i];
        }

        if (send_all(socket_fd, init_message, sizeof(init_message)) != 0) {
            goto cleanup;
        }

        if (recv_all(socket_fd, peer_public_key,
                     sizeof(peer_public_key)) != 0) {
            goto cleanup;
        }
    } else {
        /* Device2 receives Device1's public key and salt. */
        if (recv_all(socket_fd, init_message,
                     sizeof(init_message)) != 0) {
            goto cleanup;
        }

        for (size_t i = 0; i < CONTROL_PUBLIC_KEY_LEN; i++) {
            peer_public_key[i] = init_message[i];
        }

        for (size_t i = 0; i < HKDF_SALT_LEN; i++) {
            salt[i] = init_message[CONTROL_PUBLIC_KEY_LEN + i];
        }

        /* Device2 sends its public key in response. */
        if (send_all(socket_fd, public_key, sizeof(public_key)) != 0) {
            goto cleanup;
        }
    }

    if (handshake_derive_shared_secret(
            private_key,
            peer_public_key,
            shared_secret) != 1) {
        goto cleanup;
    }

    if (session_init(session, role, shared_secret, salt) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    EVP_PKEY_free(private_key);

    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(peer_public_key, sizeof(peer_public_key));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(init_message, sizeof(init_message));

    return result;
}