#!/bin/bash

# Nmap Scan Module
# Usage: nmap_scan <host_list> <output_dir>

nmap_scan() {
    local host_list="$1"
    local output_dir="$2"

    mkdir -p "$output_dir"

    echo "[+] Running Nmap scans on discovered hosts..."

    while read -r host; do
        if [[ -n "$host" ]]; then
            echo "[+] Scanning $host..."
            nmap -sV -O -T4 -Pn "$host" \
                -oN "$output_dir/${host}_nmap.txt" \
                -oX "$output_dir/${host}_nmap.xml"
        fi
    done < "$host_list"

    echo "[+] Nmap scanning complete."
}
