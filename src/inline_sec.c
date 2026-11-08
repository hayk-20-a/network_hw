
#include "gateway.h"
#include "control_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
                "Device1: %s 1 <Device2_IP> <port>\n"
                "Device2: %s 2 <port>\n",
                argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    int mode = atoi(argv[1]);
    int port;
    int control_fd;

    if (mode == 1 && argc == 4) {
        port = atoi(argv[3]);
        control_fd = control_connect(argv[2], port);
    } else if (mode == 2 && argc == 3) {
        port = atoi(argv[2]);
        control_fd = control_listen_accept(port);
    } else {
        fprintf(stderr, "Invalid arguments\n");
        return EXIT_FAILURE;
    }

    if (control_fd < 0) {
        fprintf(stderr, "[-] Control connection failed\n");
        return EXIT_FAILURE;
    }

    GatewayContext context;
    memset(&context, 0, sizeof(context));

    context.role = (mode == 1)
        ? SESSION_DEVICE1
        : SESSION_DEVICE2;

    context.control_socket = control_fd;

    printf("[+] Control channel connected\n");
    printf("[+] Starting Device%d gateway\n", mode);

    int result = gateway_run(&context);

    session_cleanup(&context.session);
    close(control_fd);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
