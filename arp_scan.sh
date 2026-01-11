#!/bin/bash

# ARP Scan Module
# Usage: arp_scan <interface> <target> <output_dir>

arp_scan() {
    local interface="$1"
    local target="$2"
    local output_dir="$3"

    mkdir -p "$output_dir"

    echo "[+] Running ARP scan on $target using $interface..."
    sudo arp-scan --interface="$interface" "$target" \
        | tee "$output_dir/arp-scan.txt"

    # Extract live hosts
    grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" "$output_dir/arp-scan.txt" \
        | sort -u > "$output_dir/live_hosts.txt"

    echo "[+] ARP scan complete. Live hosts saved to live_hosts.txt"
}
