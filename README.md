# Transparent Inline TCP Security Gateway (Bump-in-the-Wire)

A Linux-based transparent inline security proxy operating between two network devices (`Device1` and `Device2`). The gateway captures selected TCP/IPv4 traffic, performs key exchange using Diffie–Hellman, encrypts/decrypts TCP payloads in-place using **AES-256-GCM**, recalculates protocol checksums, and forwards modified packets directly without UDP encapsulation or custom tunnel headers.

---

## 🏗 Network Topology

```text
[ PC1 ] <---> (eth0) [ Device 1 ] (eth1) <===[ Encrypted TCP ]===> (eth1) [ Device 2 ] (eth0) <---> [ PC2 ]
```

* **PC1 / PC2**: End-host endpoints communicating via TCP.
* **Device 1 (Encryptor)**: Intercepts outbound TCP traffic, encrypts the TCP payload using AES-256-GCM, appends an authentication tag, recalculates TCP/IP checksums, and forwards the packet.
* **Device 2 (Decryptor)**: Intercepts encrypted packets, verifies the AES-GCM authentication tag, decrypts the payload to plaintext, recalculates checksums, and delivers the original packet to PC2.

---

## 🔐 Key Features & Security Architecture

1. **In-Place Payload Encryption**: Encrypts only the TCP payload of matching traffic. IPv4 and TCP headers remain intact to preserve standard routing behavior.
2. **AES-256-GCM Authenticated Encryption**: Guarantees confidentiality and payload integrity via 128-bit authentication tags.
3. **Unique Nonce Generation**: Employs a unique 96-bit Nonce per encrypted packet within a session, derived via a monotonic sequence counter combined with salt.
4. **Header Checksum Integrity**: Automatically recomputes IPv4 header checksums and TCP pseudo-header checksums after payload modification to prevent packet drop by intermediate routers or end hosts.
5. **Zero-Encapsulation Tunneling**: Operates without wrapping traffic inside IPsec, WireGuard, or UDP encapsulation headers.

---

## 🛠 Prerequisites & Dependencies

Operating system requirement: **Linux (Debian/Ubuntu recommended)**.

Install required dependencies:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libnetfilter-queue-dev libssl-dev iptables
```

---

## 🚀 Build & Execution

### 1. Compilation

Compile the binary using `gcc` or `make`:

```bash
gcc -O2 inline_sec.c -o inline_sec -lnetfilter_queue -lcrypto
```

### 2. Enable IP Forwarding

Enable packet forwarding on both **Device 1** and **Device 2**:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### 3. Set Up NFQUEUE Rules (`iptables`)

Redirect target TCP traffic to `NFQUEUE` (Queue `0`):

**On Device 1 (Encryptor Node):**
```bash
sudo iptables -A FORWARD -p tcp -s <PC1_IP> -d <PC2_IP> -j NFQUEUE --queue-num 0
```

**On Device 2 (Decryptor Node):**
```bash
sudo iptables -A FORWARD -p tcp -s <PC1_IP> -d <PC2_IP> -j NFQUEUE --queue-num 0
```

---

## 🧪 Testing & Verification

1. **Start Security Gateway Applications**:
   * On **Device 1**:
     ```bash
     sudo ./inline_sec 1
     ```
   * On **Device 2**:
     ```bash
     sudo ./inline_sec 2
     ```

2. **Establish Target Traffic**:
   * Start a listener on **PC2**:
     ```bash
     nc -l -p 8080
     ```
   * Connect from **PC1**:
     ```bash
     nc <PC2_IP> 8080
     ```

3. **Observe Gateway Logs**:
   * **Device 1 Output**: `[Device 1] Encrypted packet (12 -> 28 bytes)`
   * **Device 2 Output**: `[Device 2] Decrypted packet (28 -> 12 bytes)`

4. **Packet Inspection**:
   Run `tcpdump` on the link between `Device 1` and `Device 2` to confirm payload bytes are fully encrypted while IP/TCP packet headers remain intact:
   ```bash
   sudo tcpdump -i eth1 -X -nn "tcp port 8080"
   ```

---

