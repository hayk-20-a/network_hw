#ifndef CONTROL_H
#define CONTROL_H

#include "session.h"

/*
 * Perform the X25519 handshake over an already-connected TCP socket.
 *
 * Device1 initiates the handshake.
 * Device2 responds.
 *
 * Returns 0 on success, -1 on failure.
 */
int control_handshake(int socket_fd, SessionRole role, Session *session);

#endif