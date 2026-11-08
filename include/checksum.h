#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "packet.h"

/*
 * Recalculate IPv4 and TCP checksums for a parsed packet.
 *
 * The IPv4 checksum covers the IPv4 header.
 * The TCP checksum covers the TCP segment and IPv4 pseudo-header.
 *
 * Returns 1 on success, 0 on invalid input.
 */
int packet_update_checksums(PacketView *view);

#endif /* CHECKSUM_H */