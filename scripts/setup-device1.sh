#!/bin/bash
set -euo pipefail

PC1_IP="${PC1_IP:?Set PC1_IP}"
PC2_IP="${PC2_IP:?Set PC2_IP}"

QUEUE_NUM=0

iptables -I FORWARD 1 \
    -s "$PC1_IP" -d "$PC2_IP" \
    -p tcp \
    -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass

echo "[+] Device1 NFQUEUE rule installed"