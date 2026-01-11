#!/bin/bash

# p0f Passive Fingerprinting Module
# Usage: p0f_scan <interface> <output_dir>

p0f_scan() {
    local interface="$1"
    local output_dir="$2"

    mkdir -p "$output_dir"

    echo "[+] Starting passive fingerprinting with p0f on $interface..."
    sudo timeout 60 p0f -i "$interface" -o "$output_dir/p0f.log"

    echo "[+] p0f capture complete. Output saved to p0f.log"
}
