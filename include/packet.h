
#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>

#define IPV4_MIN_HEADER_LEN 20
#define TCP_MIN_HEADER_LEN  20

typedef struct {
    uint8_t *packet;

    uint8_t *ipv4_header;
    uint8_t *tcp_header;
    uint8_t *payload;

    size_t packet_len;
    size_t ipv4_header_len;
    size_t tcp_header_len;
    size_t payload_len;

    uint16_t ipv4_total_len;
} PacketView;

/*
 * Parse an IPv4 packet carrying TCP.
 *
 * Returns 1 if the packet is valid and supported.
 * Returns 0 if parsing fails or the packet is unsupported.
 *
 * Fragmented IPv4 packets are rejected because this parser
 * expects a complete TCP segment.
 */
int packet_parse_ipv4_tcp(
    uint8_t *packet,
    size_t packet_len,
    PacketView *view
);

#endif /* PACKET_H */
