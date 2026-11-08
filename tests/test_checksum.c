#include "checksum.h"

#include <stdio.h>
#include <string.h>

static void write_u16_be(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xFF);
}

static uint16_t read_u16_be(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

int main(void)
{
    uint8_t packet[45] = {0};
    PacketView view;

    packet[0] = 0x45;
    write_u16_be(&packet[2], sizeof(packet));
    packet[8] = 64;
    packet[9] = 6;

    /* Source: 192.168.1.10 */
    packet[12] = 192;
    packet[13] = 168;
    packet[14] = 1;
    packet[15] = 10;

    /* Destination: 192.168.1.20 */
    packet[16] = 192;
    packet[17] = 168;
    packet[18] = 1;
    packet[19] = 20;

    /* TCP header */
    packet[20 + 12] = 0x50;

    memcpy(&packet[40], "Hello", 5);

    if (!packet_parse_ipv4_tcp(packet, sizeof(packet), &view)) {
        printf("[FAIL] Packet parsing\n");
        return 1;
    }

    if (!packet_update_checksums(&view)) {
        printf("[FAIL] Checksum calculation\n");
        return 1;
    }

    uint16_t ip_checksum = read_u16_be(&packet[10]);
    uint16_t tcp_checksum = read_u16_be(&packet[36]);

    if (ip_checksum == 0 || tcp_checksum == 0) {
        printf("[FAIL] Checksum unexpectedly zero\n");
        return 1;
    }

    printf("[PASS] IPv4 and TCP checksums calculated\n");

    /* Verify recalculation is deterministic */
    if (!packet_update_checksums(&view)) {
        printf("[FAIL] Checksum recalculation\n");
        return 1;
    }

    if (ip_checksum != read_u16_be(&packet[10]) ||
        tcp_checksum != read_u16_be(&packet[36])) {
        printf("[FAIL] Checksum recalculation is inconsistent\n");
        return 1;
    }

    printf("[PASS] Checksum recalculation is deterministic\n");

    printf("\nAll checksum tests passed!\n");

    return 0;
}