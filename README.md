# Hybrid Recon Framework

A modular, operator‑focused reconnaissance framework for Linux environments. This tool automates ARP‑based discovery, passive fingerprinting, active enumeration, and reporting using a clean, extensible architecture. Designed for cybersecurity students, SOC analysts, and red‑team operators who want a reliable, repeatable recon workflow.

---

## Features

### **1. Discovery**
- ARP‑based host discovery using `arp-scan`
- Automatic extraction of live hosts
- Clean output directory structure

### **2. Passive Fingerprinting**
- OS and behavior inference using `p0f`
- Zero‑packet passive analysis

### **3. Active Enumeration**
- Parallelized Nmap scanning
- Service detection, OS fingerprinting, and banner grabbing

### **4. Deep Enumeration**
- SMB enumeration (`enum4linux`)
- SMB share listing (`smbclient`)
- SNMP probing (`snmpwalk`)
- Modular design for adding more tools

### **5. CVE Lookup (Pluggable)**
- Placeholder module for integrating:
  - searchsploit
  - nmap vulners
  - custom CVE APIs

### **6. Reporting**
- Auto‑generated HTML report
- Summaries of:
  - Discovered hosts
  - Open ports
  - Service banners
  - Enumeration results
  - CVE notes (placeholder)

---

## Usage


Example:

./hybrid_recon_framework.sh 192.168.1.0/24


A menu will appear with options for:
- Full hybrid recon
- Quick recon
- Report generation

---

## Output Structure

recon_YYYYMMDD_HHMMSS/
├── arp/
├── p0f/
├── nmap/
├── enum/
├── logs/
├── report/
└── tmp/

---

##  Requirements

Install the following tools:

---

##  Roadmap

- [ ] Full CVE lookup integration  
- [ ] BloodHound data collection  
- [ ] Markdown → PDF reporting  
- [ ] Python rewrite (modular architecture)  
- [ ] Packaging as a .deb tool  
- [ ] Web dashboard (Flask/FastAPI)  

---

##  Contact

Connect with me on LinkedIn:  
https://www.linkedin.com/in/easton-childress-99248127b



