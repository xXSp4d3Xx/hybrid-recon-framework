#!/bin/bash

# SMB Enumeration Module
# Usage: enum_smb <host> <output_dir>

enum_smb() {
    local host="$1"
    local output_dir="$2"

    mkdir -p "$output_dir"

    echo "[+] Enumerating SMB on $host..."

    enum4linux -a "$host" > "$output_dir/${host}_enum4linux.txt"
    smbclient -L "//$host" -N > "$output_dir/${host}_smbclient.txt"

    echo "[+] SMB enumeration complete for $host."
}
