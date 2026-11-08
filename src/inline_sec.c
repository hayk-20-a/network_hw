
#include "gateway.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <mode: 1=Device1, 2=Device2> <control_socket_fd>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    char *end = NULL;

    long mode = strtol(argv[1], &end, 10);
    if (*end != '\0' || (mode != 1 && mode != 2)) {
        fprintf(stderr, "Invalid mode. Use 1 or 2.\n");
        return EXIT_FAILURE;
    }

    end = NULL;
    long socket_fd = strtol(argv[2], &end, 10);

    if (*end != '\0' || socket_fd < 0) {
        fprintf(stderr, "Invalid control socket file descriptor.\n");
        return EXIT_FAILURE;
    }

    GatewayContext context;
    memset(&context, 0, sizeof(context));

    context.role = (mode == 1)
        ? SESSION_DEVICE1
        : SESSION_DEVICE2;

    context.control_socket = (int)socket_fd;
    context.session_established = 0;

    printf("[+] Starting gateway as Device %ld\n", mode);

    int result = gateway_run(&context);

    session_cleanup(&context.session);

    return (result == 0)
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}
