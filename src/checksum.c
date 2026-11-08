#include "checksum.h"

#include <stddef.h>
#include <stdint.h>

static uint32_t checksum_add(
    uint32_t sum,
    const uint8_t *data,
    size_t len)
{
    while (len >= 2) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }

    if (len == 1)
        sum += (uint32_t)data[0] << 8;

    return sum;
}

static uint16_t checksum_finalize(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFFU) + (sum >> 16);

    return (uint16_t)~sum;
}

static uint16_t checksum_compute(
    const uint8_t *data,
    size_t len)
{
    return checksum_finalize(checksum_add(0, data, len));
}

static void write_u16_be(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xFF);
}

int packet_update_checksums(PacketView *view)
{
    uint8_t *ip;
    uint8_t *tcp;
    uint8_t pseudo_header[12];

    size_t ip_header_len;
    size_t tcp_segment_len;

    uint16_t tcp_checksum;

    if (view == NULL ||
        view->ipv4_header == NULL ||
        view->tcp_header == NULL)
        return 0;

    ip = view->ipv4_header;
    tcp = view->tcp_header;

    ip_header_len = view->ipv4_header_len;

    if (ip_header_len < 20 || ip_header_len > 60)
        return 0;

    if (view->ipv4_total_len < ip_header_len)
        return 0;

    tcp_segment_len =
        (size_t)view->ipv4_total_len - ip_header_len;

    if (tcp_segment_len < 20 || tcp_segment_len > 65535)
        return 0;

    if (tcp_segment_len > view->packet_len - ip_header_len)
        return 0;

    /*
     * Recalculate IPv4 header checksum.
     */
    ip[10] = 0;
    ip[11] = 0;

    write_u16_be(
        &ip[10],
        checksum_compute(ip, ip_header_len));

    /*
     * Build IPv4 pseudo-header for TCP checksum:
     * source address, destination address,
     * zero, protocol, TCP segment length.
     */
    pseudo_header[0] = ip[12];
    pseudo_header[1] = ip[13];
    pseudo_header[2] = ip[14];
    pseudo_header[3] = ip[15];

    pseudo_header[4] = ip[16];
    pseudo_header[5] = ip[17];
    pseudo_header[6] = ip[18];
    pseudo_header[7] = ip[19];

    pseudo_header[8] = 0;
    pseudo_header[9] = 6;

    write_u16_be(
        &pseudo_header[10],
        (uint16_t)tcp_segment_len);

    /*
     * Recalculate TCP checksum.
     */
    tcp[16] = 0;
    tcp[17] = 0;

    uint32_t sum = checksum_add(0, pseudo_header, sizeof(pseudo_header));
    sum = checksum_add(sum, tcp, tcp_segment_len);

    tcp_checksum = checksum_finalize(sum);

    write_u16_be(&tcp[16], tcp_checksum);

    return 1;
}