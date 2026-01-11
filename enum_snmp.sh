#!/bin/bash

# SNMP Enumeration Module
# Usage: enum_snmp <host> <output_dir>

enum_snmp() {
    local host="$1"
    local output_dir="$2"

    mkdir -p "$output_dir"

    echo "[+] Checking SNMP on $host..."

    snmpwalk -v2c -c public "$host" \
        > "$output_dir/${host}_snmpwalk.txt" 2>/dev/null

    if [[ -s "$output_dir/${host}_snmpwalk.txt" ]]; then
        echo "[+] SNMP data retrieved from $host."
    else
        echo "[-] No SNMP response from $host."
        rm "$output_dir/${host}_snmpwalk.txt"
    fi
}
