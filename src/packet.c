
#include "packet.h"

#include <string.h>

static uint16_t read_u16_be(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

int packet_parse_ipv4_tcp(
    uint8_t *packet,
    size_t packet_len,
    PacketView *view)
{
    size_t ipv4_header_len;
    size_t tcp_header_len;
    uint16_t ipv4_total_len;
    uint16_t fragment_field;
    uint8_t protocol;
    uint8_t version;
    uint8_t tcp_data_offset;

    if (packet == NULL || view == NULL)
        return 0;

    memset(view, 0, sizeof(*view));

    if (packet_len < IPV4_MIN_HEADER_LEN)
        return 0;

    version = packet[0] >> 4;

    if (version != 4)
        return 0;

    ipv4_header_len = (size_t)(packet[0] & 0x0F) * 4;

    if (ipv4_header_len < IPV4_MIN_HEADER_LEN ||
        ipv4_header_len > packet_len)
        return 0;

    ipv4_total_len = read_u16_be(&packet[2]);

    if (ipv4_total_len < ipv4_header_len ||
        ipv4_total_len > packet_len)
        return 0;

    protocol = packet[9];

    /* TCP protocol number */
    if (protocol != 6)
        return 0;

    fragment_field = read_u16_be(&packet[6]);

    /*
     * Reject fragmented IPv4 packets:
     * MF flag or non-zero fragment offset.
     */
    if ((fragment_field & 0x3FFF) != 0)
        return 0;

    if ((size_t)ipv4_total_len <
        ipv4_header_len + TCP_MIN_HEADER_LEN)
        return 0;

    tcp_data_offset = packet[ipv4_header_len + 12] >> 4;
    tcp_header_len = (size_t)tcp_data_offset * 4;

    if (tcp_header_len < TCP_MIN_HEADER_LEN)
        return 0;

    if (tcp_header_len >
        (size_t)ipv4_total_len - ipv4_header_len)
        return 0;

    view->packet = packet;

    view->ipv4_header = packet;
    view->tcp_header = packet + ipv4_header_len;
    view->payload = packet + ipv4_header_len + tcp_header_len;

    view->packet_len = packet_len;
    view->ipv4_header_len = ipv4_header_len;
    view->tcp_header_len = tcp_header_len;

    view->payload_len =
        (size_t)ipv4_total_len -
        ipv4_header_len -
        tcp_header_len;

    view->ipv4_total_len = ipv4_total_len;

    return 1;
}
