# RedAudit v2.7.0 User Manual

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](MANUAL_ES.md)

**Version**: 2.7.0  
**Target Audience**: Security Analysts, Penetration Testers, Systems Administrators  
**License**: GPLv3

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Architecture](#3-architecture)
4. [External Tools](#4-external-tools)
5. [Scan Modes](#5-scan-modes)
6. [Scan Workflow](#6-scan-workflow)
7. [Encryption](#7-encryption)
8. [Monitoring](#8-monitoring)
9. [Report Decryption](#9-report-decryption)
10. [Troubleshooting](#10-troubleshooting)
11. [Glossary](#11-glossary)
12. [Legal Notice](#12-legal-notice)

---

## 1. Introduction

RedAudit is an automated network auditing tool designed for Kali Linux and Debian-based systems. It orchestrates multiple security tools (nmap, whatweb, nikto, testssl.sh, searchsploit, and more) through an intelligent workflow that adapts to discovered services.

**Key Features:**

- Automatic service detection and targeted deep scanning
- **Pre-scan asyncio engine** for fast port discovery (v2.7)
- Exploit intelligence via ExploitDB integration
- SSL/TLS vulnerability analysis
- Encrypted report generation (AES-128 + PBKDF2)
- **SIEM-compatible JSON output** (v2.7)
- Progress monitoring with heartbeat system
- Bilingual support (English/Spanish)

---

## 2. Installation

### System Requirements

| Requirement | Minimum |
|:------------|:--------|
| **OS** | Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS |
| **Python** | 3.9+ |
| **Privileges** | Root/Sudo (required for raw socket access) |

### Quick Install

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### Shell Activation

| Distribution | Shell | Command |
|:-------------|:------|:--------|
| Kali Linux (2020.3+) | Zsh | `source ~/.zshrc` |
| Debian / Ubuntu / Parrot | Bash | `source ~/.bashrc` |

---

## 3. Architecture

RedAudit v2.6 is organized as a modular Python package:

| Module | Purpose |
|:-------|:--------|
| `redaudit/core/auditor.py` | Main orchestrator, thread management |
| `redaudit/core/scanner.py` | Nmap integration, deep scans, enrichment |
| `redaudit/core/prescan.py` | Asyncio fast port discovery (v2.7) |
| `redaudit/core/crypto.py` | Encryption (PBKDF2 key derivation, Fernet) |
| `redaudit/core/network.py` | Network interface detection |
| `redaudit/core/reporter.py` | JSON/TXT + SIEM-compatible report generation |
| `redaudit/utils/constants.py` | Configuration constants |
| `redaudit/utils/i18n.py` | Internationalization strings |

**Invocation:**

```bash
# Using alias (after installation)
sudo redaudit

# Using Python module
sudo python3 -m redaudit --help
```

---

## 4. External Tools

RedAudit integrates 11 external security tools. Each activates under specific conditions:

### Tool Activation Matrix

| Tool | Trigger Condition | Scan Mode | Output Location |
|:-----|:------------------|:----------|:----------------|
| **nmap** | Always | All | `host.ports[]` |
| **searchsploit** | Service has version detected | All | `ports[].known_exploits` |
| **whatweb** | HTTP/HTTPS port detected | All | `vulnerabilities[].whatweb` |
| **nikto** | HTTP/HTTPS port detected | Completo only | `vulnerabilities[].nikto_findings` |
| **curl** | HTTP/HTTPS port detected | All | `vulnerabilities[].curl_headers` |
| **wget** | HTTP/HTTPS port detected | All | `vulnerabilities[].wget_headers` |
| **openssl** | HTTPS port detected | All | `vulnerabilities[].tls_info` |
| **testssl.sh** | HTTPS port detected | Completo only | `vulnerabilities[].testssl_analysis` |
| **tcpdump** | During Deep Scan | All (if triggered) | `deep_scan.pcap_capture` |
| **tshark** | After tcpdump capture | All (if triggered) | `deep_scan.pcap_capture.tshark_summary` |
| **dig** | After port scan | All | `host.dns.reverse` |
| **whois** | Public IPs only | All | `host.dns.whois_summary` |

### Activation Flow

```text
Discovery (nmap -sn)
    │
    ▼
Port Scan (nmap -sV)
    │
    ├── Service has version? ──▶ searchsploit
    │
    ├── HTTP/HTTPS detected? ──▶ whatweb, curl, wget
    │   └── Completo mode? ──▶ nikto
    │
    ├── HTTPS detected? ──▶ openssl
    │   └── Completo mode? ──▶ testssl.sh
    │
    └── Deep Scan triggered?
        ├── tcpdump (traffic capture)
        └── tshark (protocol summary)
    │
    ▼
Enrichment: dig (reverse DNS), whois (public IPs)
```

---

## 5. Scan Modes

| Mode | Description | Use Case |
|:-----|:------------|:---------|
| **Rápido** | Discovery only (`nmap -sn`) | Quick host enumeration |
| **Normal** | Top ports + service versions | Standard security audit |
| **Completo** | Full ports + scripts + nikto + testssl | Comprehensive penetration test |

### CLI Options

```bash
# Non-interactive with specific mode
sudo python3 -m redaudit --target 192.168.1.0/24 --mode completo

# Adjust concurrency with jitter rate-limiting (v2.7)
sudo python3 -m redaudit --threads 4 --rate-limit 2

# Enable pre-scan for faster discovery (v2.7)
sudo python3 -m redaudit --target 192.168.1.0/24 --prescan
```

---

## 6. Scan Workflow

### Phase 1: Discovery

ICMP Echo + ARP sweep to identify live hosts.

### Phase 2: Port Enumeration

Parallel nmap scans based on selected mode.

### Phase 3: Adaptive Deep Scan

Automatically triggered when a host:

- Has more than 8 open ports
- Has suspicious services (socks, proxy, vpn, tor, nagios)
- Has 3 or fewer open ports
- Has open ports but no version information

**2-Phase Strategy:**

1. **Phase 1**: `nmap -A -sV -Pn -p- --version-intensity 9`
   - If MAC/OS found → Skip Phase 2
2. **Phase 2**: `nmap -O -sSU -Pn -p- --max-retries 2`
   - UDP + OS fallback

### Phase 4: Traffic Capture

If `tcpdump` is available, captures 50 packets (15s) during Deep Scan.
If `tshark` is available, generates protocol summary.

### Phase 5: Enrichment

- **dig**: Reverse DNS lookup for all hosts
- **whois**: Ownership info for public IPs only

---

## 7. Encryption

### Specification

| Parameter | Value |
|:----------|:------|
| **Algorithm** | AES-128-CBC (Fernet) |
| **Key Derivation** | PBKDF2HMAC-SHA256 |
| **Iterations** | 480,000 (exceeds OWASP 310,000) |
| **Salt** | 16 random bytes per session |
| **Password Minimum** | 12 characters + complexity |
| **File Permissions** | 0o600 (owner read/write only) |

### Usage

```bash
# Interactive - prompts for password
sudo python3 -m redaudit --encrypt

# Non-interactive - specify password
sudo python3 -m redaudit --encrypt --encrypt-password "MySecurePass123"
```

---

## 8. Monitoring

### Heartbeat System

A background thread monitors scan progress every 60 seconds:

| State | Condition | Action |
|:------|:----------|:-------|
| Active | Activity < 60s | Normal operation |
| Busy | 60s < Activity < 300s | Warning log |
| Silent | Activity > 300s | Alert (do NOT abort) |

**Logs**: `~/.redaudit/logs/redaudit_YYYYMMDD.log`

---

## 9. Report Decryption

Encrypted reports (`.json.enc`, `.txt.enc`) require the password and `.salt` file.

```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

1. Locates `report.salt` in same directory
2. Prompts for password
3. Derives key and decrypts
4. Outputs `report.decrypted.json`

---

## 10. Troubleshooting

| Issue | Cause | Solution |
|:------|:------|:---------|
| "Encryption missing" | Missing dependency | `sudo apt install python3-cryptography` |
| Few ports found | Host filtering packets | Automatic Deep Scan will attempt bypass |
| Scan appears stuck | Slow/filtered network | Check heartbeat logs; wait 8-10 min |
| VPN not detected | Interface naming | RedAudit auto-detects tun0/tap0 |

**Verification script:**

```bash
bash redaudit_verify.sh
```

---

## 11. Glossary

| Term | Definition |
|:-----|:-----------|
| **Deep Scan** | Automated aggressive scan for hosts with incomplete data |
| **Fernet** | Symmetric encryption (AES-128-CBC + HMAC-SHA256) |
| **Heartbeat** | Background thread monitoring process health |
| **Jitter** | Random variance (±30%) added to rate-limiting for IDS evasion (v2.7) |
| **PBKDF2** | Password-Based Key Derivation Function 2 |
| **Pre-scan** | Asyncio-based fast port discovery before nmap (v2.7) |
| **Rate Limit** | Artificial delay between scan operations |
| **Salt** | Random bytes combined with password for unique key |
| **SIEM** | Security Information and Event Management |

---

## 12. Legal Notice

This tool is for **authorized security auditing only**.

Usage without written consent of the network owner is illegal. The authors accept no liability for unauthorized use or resulting damages.

### License

RedAudit is licensed under the **GNU General Public License v3.0 (GPLv3)**.  
See [LICENSE](../LICENSE) for full terms.
