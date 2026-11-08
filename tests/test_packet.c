
#include "packet.h"

#include <stdio.h>
#include <string.h>

static void write_u16_be(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xFF);
}

int main(void)
{
    uint8_t packet[40 + 5] = {0};
    PacketView view;

    /* IPv4 header */
    packet[0] = 0x45; /* IPv4, 20-byte header */
    write_u16_be(&packet[2], sizeof(packet));
    write_u16_be(&packet[6], 0); /* No fragmentation */
    packet[9] = 6; /* TCP */

    /* TCP header */
    packet[20 + 12] = 0x50; /* 20-byte TCP header */

    memcpy(&packet[40], "Hello", 5);

    /* Test 1: Valid IPv4/TCP packet */
    if (!packet_parse_ipv4_tcp(packet, sizeof(packet), &view)) {
        printf("[FAIL] Valid packet rejected\n");
        return 1;
    }

    if (view.ipv4_header_len != 20 ||
        view.tcp_header_len != 20 ||
        view.payload_len != 5 ||
        memcmp(view.payload, "Hello", 5) != 0) {
        printf("[FAIL] Incorrect packet view\n");
        return 1;
    }

    printf("[PASS] Valid IPv4/TCP packet parsing\n");

    /* Test 2: Reject non-TCP protocol */
    packet[9] = 17; /* UDP */

    if (packet_parse_ipv4_tcp(packet, sizeof(packet), &view)) {
        printf("[FAIL] UDP packet accepted\n");
        return 1;
    }

    printf("[PASS] Non-TCP packet rejection\n");

    /* Test 3: Reject malformed IPv4 header length */
    packet[9] = 6;
    packet[0] = 0x44; /* IPv4 header length = 16 bytes */

    if (packet_parse_ipv4_tcp(packet, sizeof(packet), &view)) {
        printf("[FAIL] Malformed IPv4 header accepted\n");
        return 1;
    }

    printf("[PASS] Malformed IPv4 header rejection\n");

    /* Test 4: Reject fragmented packet */
    packet[0] = 0x45;
    write_u16_be(&packet[6], 0x2000); /* MF flag */

    if (packet_parse_ipv4_tcp(packet, sizeof(packet), &view)) {
        printf("[FAIL] Fragmented packet accepted\n");
        return 1;
    }

    printf("[PASS] Fragmented packet rejection\n");

    printf("\nAll packet parser tests passed!\n");

    return 0;
}
