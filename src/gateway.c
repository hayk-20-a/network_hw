
#include "gateway.h"

#include "control.h"
#include "packet.h"
#include "frame.h"
#include "checksum.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

static int accept_packet(struct nfq_q_handle *queue, uint32_t id)
{
    return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}

static int drop_packet(struct nfq_q_handle *queue, uint32_t id)
{
    return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
}

static int process_packet(
    struct nfq_q_handle *queue,
    uint32_t id,
    unsigned char *packet,
    int packet_len,
    GatewayContext *context)
{
    PacketView view;

    if (packet_len <= 0)
        return accept_packet(queue, id);

    if (!packet_parse_ipv4_tcp(packet, (size_t)packet_len, &view))
        return accept_packet(queue, id);

    /* TCP packets without payload do not need framing. */
    if (view.payload_len == 0)
        return accept_packet(queue, id);

    if (!context->session_established) {
        if (control_handshake(
                context->control_socket,
                context->role,
                &context->session) != 0) {
            fprintf(stderr, "[-] Session handshake failed\n");
            return drop_packet(queue, id);
        }

        context->session_established = 1;
        printf("[+] Secure session established\n");
    }

    size_t header_len = view.ipv4_header_len + view.tcp_header_len;
    size_t output_capacity = GATEWAY_MAX_PACKET_SIZE - header_len;

    unsigned char *new_payload = malloc(output_capacity);
    if (new_payload == NULL) {
        perror("malloc");
        return drop_packet(queue, id);
    }

    size_t new_payload_len = 0;
    int result;

    if (context->role == SESSION_DEVICE1) {
        result = frame_encrypt(
            &context->session,
            view.payload,
            view.payload_len,
            new_payload,
            output_capacity,
            &new_payload_len);

        if (result != 1) {
            fprintf(stderr, "[-] Payload encryption failed\n");
            free(new_payload);
            return drop_packet(queue, id);
        }

        printf("[Device 1] Framed payload: %zu -> %zu bytes\n",
               view.payload_len, new_payload_len);

    } else if (context->role == SESSION_DEVICE2) {
        result = frame_decrypt(
            &context->session,
            view.payload,
            view.payload_len,
            new_payload,
            output_capacity,
            &new_payload_len);

        if (result != 1) {
            fprintf(stderr, "[-] Frame authentication/decryption failed\n");
            free(new_payload);
            return drop_packet(queue, id);
        }

        printf("[Device 2] Decrypted payload: %zu -> %zu bytes\n",
               view.payload_len, new_payload_len);

    } else {
        fprintf(stderr, "[-] Invalid gateway role\n");
        free(new_payload);
        return drop_packet(queue, id);
    }

    size_t new_packet_len = header_len + new_payload_len;

    if (new_packet_len > GATEWAY_MAX_PACKET_SIZE ||
        new_packet_len > UINT16_MAX) {
        fprintf(stderr, "[-] Modified packet is too large\n");
        free(new_payload);
        return drop_packet(queue, id);
    }

    unsigned char *new_packet = malloc(new_packet_len);
    if (new_packet == NULL) {
        perror("malloc");
        free(new_payload);
        return drop_packet(queue, id);
    }

    /* Preserve the original IPv4 and TCP headers. */
    memcpy(new_packet, packet, header_len);

    /* Replace the TCP payload with the processed payload. */
    memcpy(new_packet + header_len, new_payload, new_payload_len);

    struct iphdr *ip_header = (struct iphdr *)new_packet;
    struct tcphdr *tcp_header =
        (struct tcphdr *)(new_packet + view.ipv4_header_len);

    ip_header->tot_len = htons((uint16_t)new_packet_len);

    /*
     * Rebuild the PacketView for checksum calculation.
     */
    PacketView modified_view;

    if (!packet_parse_ipv4_tcp(
            new_packet, new_packet_len, &modified_view)) {
        fprintf(stderr, "[-] Modified packet parsing failed\n");
        free(new_packet);
        free(new_payload);
        return drop_packet(queue, id);
    }

    if (!packet_update_checksums(&modified_view)) {
        fprintf(stderr, "[-] Checksum recalculation failed\n");
        free(new_packet);
        free(new_payload);
        return drop_packet(queue, id);
    }

    int verdict = nfq_set_verdict(
        queue,
        id,
        NF_ACCEPT,
        (uint32_t)new_packet_len,
        new_packet);

    free(new_packet);
    free(new_payload);

    return verdict;
}

static int gateway_callback(
    struct nfq_q_handle *queue,
    struct nfgenmsg *message,
    struct nfq_data *data,
    void *user_data)
{
    (void)message;

    GatewayContext *context = (GatewayContext *)user_data;

    struct nfqnl_msg_packet_hdr *packet_header =
        nfq_get_msg_packet_hdr(data);

    if (packet_header == NULL)
        return accept_packet(queue, 0);

    uint32_t packet_id = ntohl(packet_header->packet_id);

    unsigned char *packet = NULL;
    int packet_len = nfq_get_payload(data, &packet);

    if (packet_len < 0 || packet == NULL)
        return accept_packet(queue, packet_id);

    return process_packet(
        queue,
        packet_id,
        packet,
        packet_len,
        context);
}

int gateway_run(GatewayContext *context)
{
    if (context == NULL) {
        fprintf(stderr, "[-] Gateway context is NULL\n");
        return -1;
    }

    struct nfq_handle *handle = nfq_open();
    if (handle == NULL) {
        perror("nfq_open");
        return -1;
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0)
        fprintf(stderr, "[!] nfq_unbind_pf failed\n");

    if (nfq_bind_pf(handle, AF_INET) < 0) {
        perror("nfq_bind_pf");
        nfq_close(handle);
        return -1;
    }

    struct nfq_q_handle *queue = nfq_create_queue(
        handle,
        GATEWAY_QUEUE_NUM,
        &gateway_callback,
        context);

    if (queue == NULL) {
        perror("nfq_create_queue");
        nfq_close(handle);
        return -1;
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET,
                     GATEWAY_MAX_PACKET_SIZE) < 0) {
        perror("nfq_set_mode");
        nfq_destroy_queue(queue);
        nfq_close(handle);
        return -1;
    }

    int fd = nfq_fd(handle);

    unsigned char buffer[8192]
        __attribute__((aligned));

    printf("[+] NFQUEUE gateway running on queue %d\n",
           GATEWAY_QUEUE_NUM);

    while (1) {
        int received = recv(fd, buffer, sizeof(buffer), 0);

        if (received < 0) {
            if (errno == EINTR)
                continue;

            perror("recv");
            break;
        }

        if (nfq_handle_packet(handle, (char *)buffer, received) < 0) {
            fprintf(stderr, "[-] nfq_handle_packet failed\n");
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return 0;
}
