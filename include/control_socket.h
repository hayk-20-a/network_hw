
#ifndef CONTROL_SOCKET_H
#define CONTROL_SOCKET_H

int control_connect(const char *ip, int port);
int control_listen_accept(int port);

#endif
