#!/bin/bash

# ====================================================
# HYBRID RECON FRAMEWORK
# Author: Easton
# Mode: Operator-grade, configurable, streamlined
# ====================================================

# --------- CONFIG DEFAULTS ---------
DEFAULT_INTERFACE="eth0"
OUTDIR_BASE="recon_$(date +%Y%m%d_%H%M%S)"

TARGET_NET="$1"
INTERFACE="$DEFAULT_INTERFACE"
OUTDIR="$OUTDIR_BASE"

# Tool tuning defaults (can be overridden by configure_scan)
NAABU_FLAGS=""
HTTPX_FLAGS="-status-code -title"
NUCLEI_SEVERITY=""

# RustScan tuning
RUSTSCAN_ULIMIT_DEFAULT="10000"
RUSTSCAN_ULIMIT="$RUSTSCAN_ULIMIT_DEFAULT"
RUSTSCAN_FLAGS=""

mkdir -p "$OUTDIR"/{arp,p0f,nmap,enum,logs,report,tmp,osint,web}

# --------- COLORS & LOGGING ---------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
RESET="\e[0m"

log() {
    local level="$1"; shift
    echo -e "${level}[$(date +%H:%M:%S)]$RESET $*" | tee -a "$OUTDIR/logs/framework.log"
}

fatal() {
    log "$RED" "[FATAL] $*"
    exit 1
}

# --------- PROGRESS HELPERS ---------
progress() {
    local msg="$1"
    echo -ne "[*] $msg...\r"
}

done_msg() {
    local msg="$1"
    echo -e "[+] $msg"
}

# --------- TOOL CHECKER / INSTALLER ---------
check_tool() {
    local tool="$1"
    local pkg="${2:-$1}"

    if ! command -v "$tool" >/dev/null 2>&1; then
        log "$YELLOW" "[!] Tool '$tool' not found."
        read -rp "    Install package '$pkg' now? (y/n): " ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            log "$GREEN" "[+] Installing $pkg ..."
            sudo apt-get update >/dev/null 2>&1
            sudo apt-get install -y "$pkg"
            if ! command -v "$tool" >/dev/null 2>&1; then
                log "$RED" "[!] '$tool' still not found after install. Skipping."
                return 1
            fi
            log "$GREEN" "[+] '$tool' installed successfully."
        else
            log "$YELLOW" "[!] Skipping installation of '$tool'. Some features may not work."
            return 1
        fi
    fi
    return 0
}

check_core_tools() {
    log "$BLUE" "[*] Checking core tools..."
    check_tool "arp-scan" "arp-scan"
    check_tool "nmap" "nmap"
    check_tool "p0f" "p0f"
    check_tool "enum4linux" "enum4linux"
    check_tool "smbclient" "samba-common-bin"
    check_tool "snmpwalk" "snmp"
    check_tool "rustscan" "rustscan"
}

# --------- CONFIGURE SCAN (TUNING) ---------
configure_scan() {
    echo
    echo -e "${CYAN}=== Scan Configuration ===${RESET}"

    read -rp "RustScan ulimit (default ${RUSTSCAN_ULIMIT_DEFAULT}): " rs_ul
    [[ -n "$rs_ul" ]] && RUSTSCAN_ULIMIT="$rs_ul"

    read -rp "RustScan extra flags (default: none): " rs_flags
    [[ -n "$rs_flags" ]] && RUSTSCAN_FLAGS="$rs_flags"

    read -rp "Naabu flags (default: none): " naabu_flags
    [[ -n "$naabu_flags" ]] && NAABU_FLAGS="$naabu_flags"

    read -rp "httpx flags (default: ${HTTPX_FLAGS}): " httpx_flags
    [[ -n "$httpx_flags" ]] && HTTPX_FLAGS="$httpx_flags"

    read -rp "Nuclei severity filter (e.g., critical,high,medium) [default: all]: " nuclei_sev
    [[ -n "$nuclei_sev" ]] && NUCLEI_SEVERITY="$nuclei_sev"

    echo
    echo -e "${GREEN}[+] Configuration saved.${RESET}"
    echo -e "${GREEN}    RustScan ulimit:   ${RUSTSCAN_ULIMIT}${RESET}"
    echo -e "${GREEN}    RustScan flags:    ${RUSTSCAN_FLAGS:-<none>}${RESET}"
    echo -e "${GREEN}    Naabu flags:       ${NAABU_FLAGS:-<default>}${RESET}"
    echo -e "${GREEN}    httpx flags:       ${HTTPX_FLAGS:-<default>}${RESET}"
    echo -e "${GREEN}    Nuclei severity:   ${NUCLEI_SEVERITY:-<all>}${RESET}"
    echo
}

# --------- BANNER & USAGE ---------
banner() {
    clear
    echo -e "${BLUE}===========================================${RESET}"
    echo -e "${BLUE}         HYBRID RECON FRAMEWORK            ${RESET}"
    echo -e "${BLUE}===========================================${RESET}"
    echo -e "Output directory: ${YELLOW}$OUTDIR${RESET}"
    echo -e "Interface:        ${YELLOW}$INTERFACE${RESET}"
    echo
}

usage() {
    echo "Usage: $0 <target_cidr> [options]"
    echo
    echo "Options:"
    echo "  -i <interface>     Network interface (default: $DEFAULT_INTERFACE)"
    echo "  -h, --help         Show this help"
    echo
    echo "Example:"
    echo "  $0 192.168.1.0/24 -i eth0"
    exit 1
}

# --------- ARG PARSING ---------
parse_args() {
    if [[ -z "$TARGET_NET" ]]; then
        usage
    fi

    shift 1
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# --------- SAFE VALIDATION ---------
validate_environment() {
    if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
        fatal "Interface '$INTERFACE' does not exist."
    fi

    if ! echo "$TARGET_NET" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
        fatal "Target '$TARGET_NET' is not a valid CIDR (e.g., 192.168.1.0/24)."
    fi
}
# ====================================================
#   CORE RECON PHASES
# ====================================================

run_arp_scan() {
    progress "ARP-SCAN on $TARGET_NET via $INTERFACE"
    log "$GREEN" "[+] ARP-SCAN on $TARGET_NET via $INTERFACE"

    sudo arp-scan --interface="$INTERFACE" "$TARGET_NET" \
        > "$OUTDIR/arp/arp-scan.txt" 2>"$OUTDIR/logs/arp-scan.log"

    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTDIR/arp/arp-scan.txt" \
        | sort -u > "$OUTDIR/arp/live_hosts.txt"

    if [[ ! -s "$OUTDIR/arp/live_hosts.txt" ]]; then
        log "$RED" "[!] No live hosts discovered by arp-scan."
    else
        log "$GREEN" "[+] Hosts discovered:"
        cat "$OUTDIR/arp/live_hosts.txt"
    fi
    done_msg "ARP-SCAN phase complete"
}

run_p0f() {
    progress "p0f passive fingerprinting on $INTERFACE"
    log "$YELLOW" "[+] p0f passive fingerprinting on $INTERFACE (20s)..."
    sudo timeout 20 p0f -i "$INTERFACE" -o "$OUTDIR/p0f/p0f.log" \
        >/dev/null 2>>"$OUTDIR/logs/p0f.log"
    log "$GREEN" "[+] p0f capture saved to p0f/p0f.log"
    done_msg "p0f phase complete"
}

# ====================================================
#   RUSTSCAN → NMAP PER-HOST (B1 MODE)
# ====================================================

run_rustscan_nmap() {
    if [[ ! -s "$OUTDIR/arp/live_hosts.txt" ]]; then
        log "$RED" "[!] No live hosts found. Skipping RustScan."
        return
    fi

    log "$CYAN" "[+] RustScan → Nmap (per-host mode)"
    mkdir -p "$OUTDIR/nmap"

    while read -r host; do
        [[ -z "$host" ]] && continue

        progress "RustScan on $host"
        log "$BLUE" "[*] RustScan: $host"

        rustscan -a "$host" \
            --ulimit "$RUSTSCAN_ULIMIT" \
            $RUSTSCAN_FLAGS \
            -- -sV -O -oN "$OUTDIR/nmap/$host.nmap" \
            > "$OUTDIR/logs/$host.rustscan.log" 2>&1

        log "$GREEN" "[+] RustScan complete for $host"
        done_msg "RustScan complete for $host"

    done < "$OUTDIR/arp/live_hosts.txt"

    log "$GREEN" "[+] RustScan → Nmap phase complete."
}

# ====================================================
#   DEEP ENUMERATION (SMB / SNMP)
# ====================================================

deep_enum_parallel() {
    if [[ ! -s "$OUTDIR/arp/live_hosts.txt" ]]; then
        log "$RED" "[!] No live hosts. Skipping deep enumeration."
        return
    fi

    progress "Deep enumeration (SMB/SNMP)"
    log "$GREEN" "[+] Deep enumeration (SMB/SNMP)..."

    while read -r host; do
        [[ -z "$host" ]] && continue
        log "$BLUE" "[*] Enum: $host"

        enum4linux -a "$host" \
            > "$OUTDIR/enum/$host.enum4linux.txt" \
            2>>"$OUTDIR/logs/$host.enum.log"

        smbclient -L "$host" -N \
            > "$OUTDIR/enum/$host.smb.txt" \
            2>>"$OUTDIR/logs/$host.smb.log"

        snmpwalk -v2c -c public "$host" \
            > "$OUTDIR/enum/$host.snmp.txt" \
            2>>"$OUTDIR/logs/$host.snmp.log" &

    done < "$OUTDIR/arp/live_hosts.txt"

    wait
    log "$GREEN" "[+] Deep enumeration complete."
    done_msg "Deep enumeration phase complete"
}
# ====================================================
#   PART 2 — ADVANCED RECON TOOLS
# ====================================================

run_advanced_recon_tools() {
    log "$CYAN" "[+] Part 2: Advanced Recon Tools"
    mkdir -p "$OUTDIR/tmp"

    # -----------------------------------------------
    # Build HTTP target list from RustScan/Nmap output
    # -----------------------------------------------
    progress "Extracting HTTP targets from Nmap results"
    : > "$OUTDIR/tmp/http_targets.txt"

    for nmap_file in "$OUTDIR/nmap/"*.nmap; do
        [[ ! -f "$nmap_file" ]] && continue

        # Extract host IP
        host=$(grep -m1 "^Nmap scan report for" "$nmap_file" | awk '{print $5}')

        # Extract open HTTP-related ports
        ports=$(grep -E "/tcp" "$nmap_file" | grep "open" \
            | awk '{print $1}' | cut -d/ -f1)

        for p in $ports; do
            case "$p" in
                80|443|8080|8000|8443)
                    echo "$host:$p" >> "$OUTDIR/tmp/http_targets.txt"
                    ;;
            esac
        done
    done

    sort -u "$OUTDIR/tmp/http_targets.txt" -o "$OUTDIR/tmp/http_targets.txt"
    done_msg "HTTP target extraction complete"

    # -----------------------------------------------
    # httpx
    # -----------------------------------------------
    if check_tool "httpx" "httpx"; then
        progress "httpx fingerprinting of HTTP services"
        log "$GREEN" "[+] httpx on HTTP services..."

        if [[ -s "$OUTDIR/tmp/http_targets.txt" ]]; then
            httpx -l "$OUTDIR/tmp/http_targets.txt" $HTTPX_FLAGS \
                -o "$OUTDIR/web/httpx_results.txt" \
                > "$OUTDIR/logs/httpx.log" 2>&1

            log "$GREEN" "[+] httpx -> web/httpx_results.txt"
        else
            log "$YELLOW" "[!] No HTTP targets for httpx."
        fi

        done_msg "httpx phase complete"
    else
        log "$YELLOW" "[!] httpx skipped."
    fi

    # -----------------------------------------------
    # nuclei
    # -----------------------------------------------
    if check_tool "nuclei" "nuclei"; then
        progress "nuclei vulnerability scan"
        log "$GREEN" "[+] nuclei vulnerability scan..."

        if [[ -s "$OUTDIR/web/httpx_results.txt" ]]; then
            if [[ -n "$NUCLEI_SEVERITY" ]]; then
                nuclei -l "$OUTDIR/web/httpx_results.txt" \
                    -severity "$NUCLEI_SEVERITY" \
                    -o "$OUTDIR/web/nuclei_results.txt" \
                    > "$OUTDIR/logs/nuclei.log" 2>&1
            else
                nuclei -l "$OUTDIR/web/httpx_results.txt" \
                    -o "$OUTDIR/web/nuclei_results.txt" \
                    > "$OUTDIR/logs/nuclei.log" 2>&1
            fi

            log "$GREEN" "[+] nuclei -> web/nuclei_results.txt"
        else
            log "$YELLOW" "[!] No HTTP targets for nuclei."
        fi

        done_msg "nuclei phase complete"
    else
        log "$YELLOW" "[!] nuclei skipped."
    fi

    # -----------------------------------------------
    # WhatWeb
    # -----------------------------------------------
    if check_tool "whatweb" "whatweb"; then
        progress "WhatWeb technology fingerprinting"
        log "$GREEN" "[+] WhatWeb on HTTP services..."

        if [[ -s "$OUTDIR/web/httpx_results.txt" ]]; then
            awk '{print $1}' "$OUTDIR/web/httpx_results.txt" \
                > "$OUTDIR/tmp/whatweb_targets.txt"

            while read -r url; do
                [[ -z "$url" ]] && continue
                log "$BLUE" "[*] WhatWeb: $url"
                whatweb "$url" \
                    >> "$OUTDIR/web/whatweb_results.txt" \
                    2>>"$OUTDIR/logs/whatweb.log"
            done < "$OUTDIR/tmp/whatweb_targets.txt"

            log "$GREEN" "[+] WhatWeb -> web/whatweb_results.txt"
        else
            log "$YELLOW" "[!] No HTTP targets for WhatWeb."
        fi

        done_msg "WhatWeb phase complete"
    else
        log "$YELLOW" "[!] WhatWeb skipped."
    fi

    # -----------------------------------------------
    # ExifTool (SMB metadata extraction)
    # -----------------------------------------------
    if check_tool "exiftool" "libimage-exiftool-perl"; then
        progress "ExifTool metadata extraction from SMB listings"
        log "$GREEN" "[+] ExifTool on SMB listings..."
        mkdir -p "$OUTDIR/osint/exif"

        for smbfile in "$OUTDIR/enum/"*.smb.txt; do
            [[ ! -f "$smbfile" ]] && continue
            host=$(basename "$smbfile" | cut -d. -f1)

            grep -E "^[ ]*[A-Za-z0-9].*\.[A-Za-z0-9]+" "$smbfile" \
                | awk '{print $1}' \
                > "$OUTDIR/tmp/${host}_smb_files.txt"

            while read -r file; do
                [[ -z "$file" ]] && continue
                log "$BLUE" "[*] ExifTool: $host -> $file"
                exiftool "$file" \
                    >> "$OUTDIR/osint/exif/${host}_exif.txt" \
                    2>>"$OUTDIR/logs/exiftool.log"
            done < "$OUTDIR/tmp/${host}_smb_files.txt"
        done

        log "$GREEN" "[+] ExifTool phase complete."
        done_msg "ExifTool phase complete"
    else
        log "$YELLOW" "[!] ExifTool skipped."
    fi

    # -----------------------------------------------
    # theHarvester
    # -----------------------------------------------
    if check_tool "theHarvester" "theharvester"; then
        progress "theHarvester OSINT collection"
        log "$GREEN" "[+] theHarvester OSINT (domain: local.lan)..."

        DOMAIN="local.lan"
        theHarvester -d "$DOMAIN" -b all \
            -f "$OUTDIR/osint/theharvester_report" \
            > "$OUTDIR/logs/theharvester.log" 2>&1

        log "$GREEN" "[+] theHarvester -> osint/theharvester_report.*"
        done_msg "theHarvester phase complete"
    else
        log "$YELLOW" "[!] theHarvester skipped."
    fi

    log "$CYAN" "[+] Part 2 complete."
}
# ====================================================
#   PART 4 — MACHINE-ASSISTED INSIGHT & RISK SCORING
# ====================================================

run_machine_insight() {
    log "$CYAN" "[+] Part 4: Machine-Assisted Insight"

    local profiles_file="$OUTDIR/tmp/host_profiles.txt"
    : > "$profiles_file"

    for nmap_file in "$OUTDIR/nmap/"*.nmap; do
        [[ ! -f "$nmap_file" ]] && continue

        host_ip=$(grep -m1 "^Nmap scan report for" "$nmap_file" | awk '{print $5}')
        [[ -z "$host_ip" ]] && continue

        log "$BLUE" "[*] Profile: $host_ip"

        os_guess=$(grep -m1 "^OS details:" "$nmap_file" | sed 's/^OS details: //')
        [[ -z "$os_guess" ]] && os_guess="Unknown"

        open_ports=$(grep "/tcp" "$nmap_file" | grep "open" | awk '{print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
        [[ -z "$open_ports" ]] && open_ports="None"

        services=$(grep "/tcp" "$nmap_file" | grep "open" | awk '{print $3}' | tr '\n' ',' | sed 's/,$//')
        [[ -z "$services" ]] && services="None"

        # Basic heuristic risk scoring
        risk_score=0
        risk_factors=()

        if echo "$open_ports" | grep -q "445"; then
            risk_score=$((risk_score + 30)); risk_factors+=("SMB (445) exposed")
        fi
        if echo "$open_ports" | grep -q "3389"; then
            risk_score=$((risk_score + 25)); risk_factors+=("RDP (3389) exposed")
        fi
        if echo "$open_ports" | grep -q "80"; then
            risk_score=$((risk_score + 10)); risk_factors+=("HTTP (80) exposed")
        fi
        if echo "$open_ports" | grep -q "443"; then
            risk_score=$((risk_score + 10)); risk_factors+=("HTTPS (443) exposed")
        fi
        if echo "$open_ports" | grep -q "22"; then
            risk_score=$((risk_score + 10)); risk_factors+=("SSH (22) exposed")
        fi
        if echo "$open_ports" | grep -q "1433\|1521\|3306\|5432"; then
            risk_score=$((risk_score + 20)); risk_factors+=("Database port exposed")
        fi

        # Nuclei findings increase risk
        if [[ -f "$OUTDIR/web/nuclei_results.txt" ]]; then
            if grep -q "$host_ip" "$OUTDIR/web/nuclei_results.txt" 2>/dev/null; then
                risk_score=$((risk_score + 20)); risk_factors+=("Nuclei findings")
            fi
        fi

        (( risk_score > 100 )) && risk_score=100

        likely_role="Unknown"
        if echo "$open_ports" | grep -q "445\|139"; then
            likely_role="File/AD Server or Windows Host"
        fi
        if echo "$open_ports" | grep -q "3389"; then
            likely_role="Windows with RDP"
        fi
        if echo "$open_ports" | grep -q "80\|443\|8080\|8000"; then
            likely_role="Web Server / Web-Exposed Host"
        fi
        if echo "$open_ports" | grep -q "22"; then
            likely_role="Linux/Unix or Appliance"
        fi

        recommendations=()
        if echo "$open_ports" | grep -q "445"; then
            recommendations+=("Run enum4linux for SMB enumeration")
            recommendations+=("Check SMB signing and anonymous access")
        fi
        if echo "$open_ports" | grep -q "3389"; then
            recommendations+=("Review RDP security and enable NLA")
        fi
        if echo "$open_ports" | grep -q "80\|443\|8080\|8000"; then
            recommendations+=("Review httpx and nuclei results for this host")
            recommendations+=("Run WhatWeb for deeper tech fingerprinting")
        fi
        if echo "$open_ports" | grep -q "22"; then
            recommendations+=("Run ssh-audit (if available)")
        fi

        if ((${#risk_factors[@]} == 0)); then
            risk_factors_str="None"
        else
            risk_factors_str=$(IFS='; '; echo "${risk_factors[*]}")
        fi

        if ((${#recommendations[@]} == 0)); then
            recommendations_str="None"
        else
            recommendations_str=$(IFS='; '; echo "${recommendations[*]}")
        fi

        {
            echo "HOST: $host_ip"
            echo "OS_GUESS: $os_guess"
            echo "OPEN_PORTS: $open_ports"
            echo "SERVICES: $services"
            echo "RISK_SCORE: $risk_score"
            echo "LIKELY_ROLE: $likely_role"
            echo "RISK_FACTORS: $risk_factors_str"
            echo "RECOMMENDATIONS: $recommendations_str"
            echo "-----"
        } >> "$profiles_file"

        log "$GREEN" "[+] Profile: $host_ip (Risk: $risk_score)"
    done

    if [[ -s "$profiles_file" ]]; then
        log "$GREEN" "[+] Host profiles -> tmp/host_profiles.txt"
    else
        log "$YELLOW" "[!] No profiles generated."
    fi

    log "$CYAN" "[+] Part 4 complete."
}

# ====================================================
#   PART 5 — ADVANCED HTML REPORTING
# ====================================================

generate_advanced_html_report() {
    log "$CYAN" "[+] Part 5: HTML Report"

    local report="$OUTDIR/report/report.html"
    mkdir -p "$OUTDIR/report"

    cat > "$report" <<EOF
<!DOCTYPE html>
<html>
<head>
<title>Hybrid Recon Report</title>
<meta charset="utf-8">
<style>
body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
h1, h2, h3 { color: #4fc3f7; }
.section { margin-bottom: 40px; padding: 20px; background: #1a1a1a; border-radius: 8px; }
.host-box { padding: 15px; margin-bottom: 20px; background: #222; border-left: 5px solid #4fc3f7; }
.low { color: #8bc34a; }
.medium { color: #ffeb3b; }
.high { color: #ff9800; }
.critical { color: #f44336; }
pre { background: #000; padding: 10px; border-radius: 6px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; border-bottom: 1px solid #333; text-align: left; }
</style>
</head>
<body>

<h1>Hybrid Recon Framework Report</h1>
<p>Generated: $(date)</p>

<div class="section">
<h2>1. Host Profiles & Risk Scores</h2>
EOF

    local profiles="$OUTDIR/tmp/host_profiles.txt"

    if [[ -s "$profiles" ]]; then
        awk '
        BEGIN { FS=": "; RS="-----\n" }
        {
            # Parse fields robustly
            host="Unknown"; os="Unknown"; openp="None"; svc="None"; score="0"; role="Unknown"; factors="None"; recs="None"
            for(i=1;i<=NF;i++){
                if ($i ~ /^HOST/) host=$(i+1)
                if ($i ~ /^OS_GUESS/) os=$(i+1)
                if ($i ~ /^OPEN_PORTS/) openp=$(i+1)
                if ($i ~ /^SERVICES/) svc=$(i+1)
                if ($i ~ /^RISK_SCORE/) score=$(i+1)
                if ($i ~ /^LIKELY_ROLE/) role=$(i+1)
                if ($i ~ /^RISK_FACTORS/) factors=$(i+1)
                if ($i ~ /^RECOMMENDATIONS/) recs=$(i+1)
            }
            color="low"
            if (score+0 >= 70) color="critical"
            else if (score+0 >= 50) color="high"
            else if (score+0 >= 30) color="medium"

            print "<div class=\"host-box\">"
            print "<h3>Host: " host "</h3>"
            print "<p><b>OS Guess:</b> " os "</p>"
            print "<p><b>Open Ports:</b> " openp "</p>"
            print "<p><b>Services:</b> " svc "</p>"
            print "<p><b>Risk Score:</b> <span class=\"" color "\">" score "</span></p>"
            print "<p><b>Likely Role:</b> " role "</p>"
            print "<p><b>Risk Factors:</b> " factors "</p>"
            print "<p><b>Recommendations:</b> " recs "</p>"
            print "</div>"
        }
        ' "$profiles" >> "$report"
    else
        echo "<p>No host profiles generated.</p>" >> "$report"
    fi

    cat >> "$report" <<EOF
</div>

<div class="section">
<h2>2. Web Fingerprinting</h2>
EOF

    if [[ -s "$OUTDIR/web/httpx_results.txt" ]]; then
        echo "<h3>HTTPX Results</h3><pre>" >> "$report"
        sed 's/&/\&amp;/g; s/</\&lt;/g' "$OUTDIR/web/httpx_results.txt" >> "$report"
        echo "</pre>" >> "$report"
    else
        echo "<p>No httpx results.</p>" >> "$report"
    fi

    if [[ -s "$OUTDIR/web/whatweb_results.txt" ]]; then
        echo "<h3>WhatWeb Results</h3><pre>" >> "$report"
        sed 's/&/\&amp;/g; s/</\&lt;/g' "$OUTDIR/web/whatweb_results.txt" >> "$report"
        echo "</pre>" >> "$report"
    else
        echo "<p>No WhatWeb results.</p>" >> "$report"
    fi

    cat >> "$report" <<EOF
</div>

<div class="section">
<h2>3. Vulnerability Findings (Nuclei)</h2>
EOF

    if [[ -s "$OUTDIR/web/nuclei_results.txt" ]]; then
        echo "<pre>" >> "$report"
        sed 's/&/\&amp;/g; s/</\&lt;/g' "$OUTDIR/web/nuclei_results.txt" >> "$report"
        echo "</pre>" >> "$report"
    else
        echo "<p>No nuclei results.</p>" >> "$report"
    fi

    cat >> "$report" <<EOF
</div>

<div class="section">
<h2>4. OSINT Summary</h2>
EOF

    if [[ -f "$OUTDIR/osint/theharvester_report.xml" ]]; then
        echo "<h3>theHarvester Output (XML)</h3><pre>" >> "$report"
        sed 's/&/\&amp;/g; s/</\&lt;/g' "$OUTDIR/osint/theharvester_report.xml" >> "$report"
        echo "</pre>" >> "$report"
    else
        echo "<p>No theHarvester results.</p>" >> "$report"
    fi

    if [[ -d "$OUTDIR/osint/exif" ]]; then
        echo "<h3>Exif Metadata</h3>" >> "$report"
        for f in "$OUTDIR/osint/exif/"*.txt; do
            [[ ! -f "$f" ]] && continue
            echo "<h4>$(basename "$f")</h4><pre>" >> "$report"
            sed 's/&/\&amp;/g; s/</\&lt;/g' "$f" >> "$report"
            echo "</pre>" >> "$report"
        done
    else
        echo "<p>No Exif metadata extracted.</p>" >> "$report"
    fi

    cat >> "$report" <<EOF
</div>

</body>
</html>
EOF

    log "$GREEN" "[+] HTML report -> $report"
}

# ====================================================
#   SCAN SUMMARY
# ====================================================

scan_summary() {
    echo
    echo -e "${CYAN}=== Scan Summary ===${RESET}"
    echo "Target network:     $TARGET_NET"
    echo "Output directory:   $OUTDIR"
    echo "Interface:          $INTERFACE"
    echo "RustScan ulimit:    $RUSTSCAN_ULIMIT"
    echo "RustScan flags:     ${RUSTSCAN_FLAGS:-<default>}"
    echo "Naabu flags:        ${NAABU_FLAGS:-<default>}"
    echo "httpx flags:        ${HTTPX_FLAGS:-<default>}"
    echo "Nuclei severity:    ${NUCLEI_SEVERITY:-<all>}"
    echo
}
# ====================================================
#   WORKFLOWS, MENU, AND ENTRY POINT
# ====================================================

full_recon_workflow() {
    banner
    check_core_tools
    validate_environment
    configure_scan

    log "$CYAN" "[*] Starting full recon workflow"
    run_arp_scan
    run_p0f
    run_rustscan_nmap
    deep_enum_parallel

    run_advanced_recon_tools
    run_machine_insight
    generate_advanced_html_report

    scan_summary
    log "$GREEN" "[+] Full recon complete. See $OUTDIR for results."
}

quick_recon_workflow() {
    banner
    check_core_tools
    validate_environment

    log "$CYAN" "[*] Starting quick recon (ARP + RustScan → Nmap)"
    run_arp_scan
    run_rustscan_nmap

    scan_summary
    log "$GREEN" "[+] Quick recon complete. See $OUTDIR for results."
}

menu() {
    parse_args "$@"

    # Ensure OUTDIR exists (recreate with timestamp if needed)
    if [[ -z "$OUTDIR" ]]; then
        OUTDIR="$OUTDIR_BASE"
    fi
    mkdir -p "$OUTDIR"/{arp,p0f,nmap,enum,logs,report,tmp,osint,web}

    while true; do
        banner
        echo -e "${CYAN}Target network:${RESET} $TARGET_NET"
        echo
        echo -e "${GREEN}1) Full Recon (All Modules + Config)${RESET}"
        echo -e "${GREEN}2) Quick Recon (ARP + RustScan → Nmap)${RESET}"
        echo -e "${GREEN}3) Configure Scan Settings${RESET}"
        echo -e "${GREEN}4) Exit${RESET}"
        echo
        read -rp "Select an option: " choice

        case "$choice" in
            1)
                full_recon_workflow
                read -rp "Press Enter to return to menu..." _
                ;;
            2)
                quick_recon_workflow
                read -rp "Press Enter to return to menu..." _
                ;;
            3)
                configure_scan
                read -rp "Press Enter to return to menu..." _
                ;;
            4)
                log "$BLUE" "[*] Exiting."
                exit 0
                ;;
            *)
                echo "Invalid choice."
                sleep 1
                ;;
        esac
    done
}

# ====================================================
#   ENTRY POINT
# ====================================================

# If script is sourced, don't run menu automatically
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    # Basic sanity: require root for some operations
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Warning:${RESET} Some tools may require root privileges. Consider running as root or with sudo."
    fi

    # Launch interactive menu
    menu "$@"
fi
