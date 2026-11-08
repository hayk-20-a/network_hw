
#include "control_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int control_connect(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

int control_listen_accept(int port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
               &reuse, sizeof(reuse));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("bind");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }

    printf("[+] Waiting for Device1 control connection on port %d...\n",
           port);

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        return -1;
    }

    close(server_fd);
    return client_fd;
}
