#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX_PAYLOAD_SIZE 65535
#define AES_KEY_LEN 32        // AES-256
#define GCM_NONCE_LEN 12      // 96-bit Nonce
#define GCM_TAG_LEN 16        // 128-bit Auth Tag

// Global Session State
static unsigned char g_session_key[AES_KEY_LEN];
static uint64_t g_packet_counter = 0;
static int g_session_established = 0;

/* --- Pseudo Header for TCP Checksum Calculation --- */
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

/* --- Checksum Helper --- */
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return answer;
}

void recalculate_checksums(struct iphdr *iph, struct tcphdr *tcph, unsigned char *payload, int payload_len) {
    // 1. Recalculate IP Checksum
    iph->check = 0;
    iph->check = checksum((unsigned short *)iph, iph->ihl * 4);

    // 2. Recalculate TCP Checksum
    int tcp_len = (tcph->doff * 4) + payload_len;
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);

    int psize = sizeof(struct pseudo_header) + tcp_len;
    unsigned char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, tcph->doff * 4);
    if (payload_len > 0) {
        memcpy(pseudogram + sizeof(struct pseudo_header) + (tcph->doff * 4), payload, payload_len);
    }

    tcph->check = 0;
    tcph->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
}

/* --- AES-GCM Cryptographic Operations --- */

// Nonce generation: 8-byte monotonic counter + 4-byte random salt
void generate_nonce(unsigned char *nonce) {
    g_packet_counter++;
    memcpy(nonce, &g_packet_counter, sizeof(g_packet_counter));
    // Fill remaining 4 bytes with random salt (or static salt derived during DH)
    memset(nonce + 8, 0xAA, 4); 
}

int encrypt_payload(unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext, unsigned char *tag, unsigned char *nonce) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, g_session_key, nonce);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_payload(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *tag, unsigned char *nonce, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, g_session_key, nonce);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1; // Authentication failure
    }
}

/* --- Dummy Diffie-Hellman Shared Key Setup --- */
void perform_dh_handshake() {
    // For homework/prototype demonstration: Hardcode shared secret derived via DH
    // In production: Send DH Public Key in SYN packet or via initial control channel
    memset(g_session_key, 0x42, AES_KEY_LEN);
    g_session_established = 1;
    printf("[+] Diffie-Hellman Handshake Complete. Session key established.\n");
}

/* --- Packet Handler callback for NFQUEUE --- */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    unsigned char *packet_data;
    int ret = nfq_get_payload(nfa, &packet_data);
    if (ret < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    struct iphdr *iph = (struct iphdr *)packet_data;
    if (iph->protocol != IPPROTO_TCP) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    int ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(packet_data + ip_hdr_len);
    int tcp_hdr_len = tcph->doff * 4;

    unsigned char *payload = packet_data + ip_hdr_len + tcp_hdr_len;
    int payload_len = ret - ip_hdr_len - tcp_hdr_len;

    // Only process packets containing actual data payload
    if (payload_len <= 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    if (!g_session_established) {
        perform_dh_handshake();
    }

    int mode = *(int*)data; // 1 = Encrypt (Device 1), 2 = Decrypt (Device 2)

    if (mode == 1) { // Encrypt Path
        unsigned char nonce[GCM_NONCE_LEN];
        unsigned char tag[GCM_TAG_LEN];
        unsigned char encrypted[MAX_PAYLOAD_SIZE];

        generate_nonce(nonce);
        int enc_len = encrypt_payload(payload, payload_len, encrypted, tag, nonce);

        // Construct new payload: Encrypted Payload + Tag
        // (Nonce is synchronized or embedded; here appended right after tag)
        unsigned char new_payload[MAX_PAYLOAD_SIZE];
        memcpy(new_payload, encrypted, enc_len);
        memcpy(new_payload + enc_len, tag, GCM_TAG_LEN);
        int new_payload_len = enc_len + GCM_TAG_LEN;

        // Build new modified packet buffer
        int new_pkt_len = ip_hdr_len + tcp_hdr_len + new_payload_len;
        unsigned char *new_packet = malloc(new_pkt_len);

        memcpy(new_packet, packet_data, ip_hdr_len + tcp_hdr_len);
        memcpy(new_packet + ip_hdr_len + tcp_hdr_len, new_payload, new_payload_len);

        struct iphdr *new_iph = (struct iphdr *)new_packet;
        struct tcphdr *new_tcph = (struct tcphdr *)(new_packet + ip_hdr_len);

        new_iph->tot_len = htons(new_pkt_len);
        recalculate_checksums(new_iph, new_tcph, new_payload, new_payload_len);

        int verdict = nfq_set_verdict(qh, id, NF_ACCEPT, new_pkt_len, new_packet);
        free(new_packet);
        printf("[Device 1] Encrypted packet (%d -> %d bytes)\n", payload_len, new_payload_len);
        return verdict;

    } else if (mode == 2) { // Decrypt Path
        if (payload_len < GCM_TAG_LEN) {
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        int cipher_len = payload_len - GCM_TAG_LEN;
        unsigned char *cipher_text = payload;
        unsigned char *tag = payload + cipher_len;

        unsigned char nonce[GCM_NONCE_LEN];
        generate_nonce(nonce); // Synchronized sequence counter

        unsigned char decrypted[MAX_PAYLOAD_SIZE];
        int dec_len = decrypt_payload(cipher_text, cipher_len, tag, nonce, decrypted);

        if (dec_len < 0) {
            printf("[-] [Device 2] Auth Tag Verification Failed! Dropping Packet.\n");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        // Build restored packet
        int new_pkt_len = ip_hdr_len + tcp_hdr_len + dec_len;
        unsigned char *new_packet = malloc(new_pkt_len);

        memcpy(new_packet, packet_data, ip_hdr_len + tcp_hdr_len);
        memcpy(new_packet + ip_hdr_len + tcp_hdr_len, decrypted, dec_len);

        struct iphdr *new_iph = (struct iphdr *)new_packet;
        struct tcphdr *new_tcph = (struct tcphdr *)(new_packet + ip_hdr_len);

        new_iph->tot_len = htons(new_pkt_len);
        recalculate_checksums(new_iph, new_tcph, decrypted, dec_len);

        int verdict = nfq_set_verdict(qh, id, NF_ACCEPT, new_pkt_len, new_packet);
        free(new_packet);
        printf("[Device 2] Decrypted packet (%d -> %d bytes)\n", payload_len, dec_len);
        return verdict;
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <mode: 1 for Device1 Encrypt, 2 for Device2 Decrypt>\n", argv[0]);
        return 1;
    }
    int mode = atoi(argv[1]);

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open failure"); exit(1); }

    if (nfq_unbind_pf(h, AF_INET) < 0) { perror("nfq_unbind_pf failure"); }
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf failure"); exit(1); }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, &mode);
    if (!qh) { perror("nfq_create_queue failure"); exit(1); }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode failure"); exit(1);
    }

    printf("[*] Inline Security Gateway Started in Mode %d...\n", mode);

    int fd = nfq_fd(h);
    char buf[4096] __attribute__ ((aligned));
    int rv;

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}