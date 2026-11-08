
#ifndef GATEWAY_H
#define GATEWAY_H

#include "session.h"

#define GATEWAY_QUEUE_NUM 0
#define GATEWAY_MAX_PACKET_SIZE 65535

typedef struct {
    SessionRole role;
    Session session;
    int control_socket;
    int session_established;
} GatewayContext;

/*
 * Start the NFQUEUE gateway.
 *
 * context:
 *   Gateway configuration and cryptographic session.
 *
 * Returns:
 *   0 on normal shutdown
 *  -1 on failure
 */
int gateway_run(GatewayContext *context);

#endif
