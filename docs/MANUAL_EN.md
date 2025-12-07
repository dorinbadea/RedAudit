# RedAudit User Manual

**Version**: 2.5
**Date**: 2025-12-07
**Target Level**: Professional Pentester / SysAdmin

---

## 📑 Table of Contents
1. [Introduction](#1-introduction)
2. [Supported Environment](#2-supported-environment)
3. [Installation](#3-installation)
4. [Quick Start](#4-quick-start)
5. [Deep Configuration](#5-deep-configuration)
    - [Concurrency & Threads](#concurrency--threads)
    - [Rate Limiting](#rate-limiting)
    - [Encryption](#encryption)
6. [Scan Logic &Phases](#6-scan-logic--phases)
7. [Decryption Guide](#7-decryption-guide)
8. [Monitoring & Heartbeat](#8-monitoring--heartbeat)
9. [Verification Script](#9-verification-script)
10. [FAQ](#10-faq)
11. [Glossary](#11-glossary)
12. [Legal Notice](#12-legal-notice)

---

## 1. Introduction
RedAudit is an automated reconnaissance framework designed to streamline the `Discovery` → `Enumeration` → `Vulnerability Assessment` pipeline. It wraps industry-standard tools (`nmap`, `whatweb`, `tcpdump`) in a robust Python concurrency model, adding layers of resilience (heartbeats, retries) and security (encryption, sanitization).

## 2. Supported Environment
- **OS**: Kali Linux (Preferred), Debian 10+, Ubuntu 20.04+.
- **Privileges**: **Root** (`sudo`) access is mandatory for:
    - SYN scanning (`nmap -sS`).
    - OS detection (`nmap -O`).
    - Raw packet capture (`tcpdump`).
- **Python**: 3.8 or higher.

## 3. Installation
RedAudit uses a consolidated installer script that handles dependencies (apt) and setup.

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
source ~/.bashrc  # Activates the alias
```

**Dependencies installed:**
- `nmap`, `python3-nmap` (Core scanning)
- `python3-cryptography` (Report encryption)
- `whatweb`, `nikto`, `tcpdump`, `tshark` (Optional enrichment)

## 4. Quick Start

### Interactive Mode
Run `redaudit` to start the interactive wizard.

**Example Session:**
```text
? Select network: 192.168.1.0/24
? Select scan mode: NORMAL
? Enter number of threads [1-16]: 6
? Enable Web Vulnerability scans? [y/N]: y
? Encrypt reports with password? [y/N]: y
```

### Non-Interactive Mode (v2.5)
For automation, use command-line arguments:

```bash
# Basic scan
sudo redaudit --target 192.168.1.0/24 --mode normal --threads 6

# Full scan with all options
sudo redaudit \
  --target 10.0.0.0/24 \
  --mode full \
  --threads 8 \
  --rate-limit 2 \
  --encrypt \
  --encrypt-password "MySecurePassword123" \
  --output /tmp/reports \
  --max-hosts 50

# With encryption (random password generated)
sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --yes

# Multiple targets
sudo redaudit --target "192.168.1.0/24,10.0.0.0/24" --mode normal

# Automation (skip legal warning)
sudo redaudit --target 192.168.1.0/24 --mode fast --yes
```

**Key CLI Arguments:**
- `--target, -t`: Target network(s) in CIDR (required for non-interactive)
- `--mode, -m`: fast/normal/full (default: normal)
- `--threads, -j`: 1-16 (default: 6)
- `--rate-limit`: Delay in seconds (default: 0)
- `--encrypt, -e`: Enable encryption
- `--encrypt-password PASSWORD`: Password for encryption (non-interactive). If omitted, a random password will be generated and displayed.
- `--output, -o`: Output directory
- `--max-hosts`: Limit number of hosts
- `--yes, -y`: Skip legal warning
- `--lang`: Language (en/es)

Run `redaudit --help` for complete list.

## 5. Deep Configuration

### Concurrency & Threads
RedAudit uses a **Thread Pool** (`concurrent.futures.ThreadPoolExecutor`) to scan hosts in parallel.
- **Nature**: These are **Python Threads**, not processes. They share memory and global interpreter state, but since Nmap is an I/O-bound subprocess, threading is highly efficient.
- **Tuning**:
    - **1-4 Threads**: Stealth mode. Use for strictly monitored networks or legacy switches susceptible to congestion.
    - **6-10 Threads (Default)**: Balanced for standard LANs.
    - **12-16 Threads**: Aggressive. Suitable for CTFs or robust, modern networks. Exceeding 16 often yields diminishing returns due to Nmap's own internal parallelism.

### Rate Limiting
To evade IDS heuristics based on connection frequency, RedAudit implements **Application-Layer Rate Limiting**.
- **Parameter**: `rate_limit_delay` (seconds).
- **Implementation**: A forced `time.sleep(DELAY)` executes before a worker thread picks up a new host task.
- **Impact**:
    - **0s**: Fire-and-forget.
    - **2s**: Adds a 2-second cooldown between host starts. In a 100-host subnet with 10 threads, this significantly spreads out the SYN packet bursts.
    - **>10s**: "Low and Slow". Drastically increases scan time but virtually eliminates simple burst detection.

### Encryption
RedAudit treats report data as sensitive material.
- **Standard**: **Fernet** (Specification compliant).
    - **Cipher**: AES-128 in CBC mode.
    - **Signing**: HMAC-SHA256.
    - **Validation**: Timestamp-aware token (TTL ignored by default).
- **Key Derivation**:
    - **Algorithm**: PBKDF2HMAC (SHA-256).
    - **Iterations**: 480,000 (exceeds OWASP recommendation of 310,000).
    - **Salt**: 16 random bytes, stored in `.salt` file.
- **Graceful Degradation** (v2.5): If `python3-cryptography` is unavailable, encryption is automatically disabled with clear warnings. No password prompts are shown.
- **File Permissions** (v2.5): All reports (encrypted and plain) use secure permissions (0o600 - owner read/write only).

## 6. Scan Logic & Phases
1.  **Discovery**: ICMP Echo (`-PE`) + ARP (`-PR`) sweep to map live hosts.
2.  **Enumeration**: Parallel Nmap scans based on mode.
3.  **Adaptive Deep Scan (Automatic)**:
    - **Triggers**: Auto-triggered if a host:
        - Has more than 8 open ports
        - Has suspicious services (socks, proxy, vpn, tor, nagios, etc.)
        - Has 3 or fewer open ports
        - Has open ports but no version information detected
    - **Strategy (2-Phases)**:
        1.  **Phase 1**: `nmap -A -sV -Pn -p- --open --version-intensity 9` (TCP Aggressive).
            - *Check*: If MAC/OS is found, stop here and skip Phase 2.
        2.  **Phase 2**: `nmap -O -sSU -Pn -p- --max-retries 2` (UDP + OS fallback, only if Phase 1 yielded no identity).
    - **Result**: Data is stored in `host.deep_scan`, including `mac_address`, `vendor`, and `phase2_skipped` flag.

4.  **Traffic Capture**:
    - As part of the **Deep Scan** process, if `tcpdump` is present, RedAudit captures a small snippet (50 packets/15s) from the host's traffic.
    - **Output**:
        - Saves `.pcap` files in your report directory (e.g., `traffic_192.168.1.1.pcap`).
        - If `tshark` is installed, a text summary is embedded in `host.deep_scan.pcap_capture`.

## 7. Decryption Guide
Encrypted reports (`.json.enc`, `.txt.enc`) are unreadable without the password and the `.salt` file.

**Usage:**
```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```
1. Script finds `report.salt` in the same directory.
2. Prompts for password.
3. Derives key and attempts decryption.
4. Outputs `report.decrypted.json` or `report.json` (if avoiding overwrite).

## 8. Monitoring & Heartbeat
Long scans (e.g., full port ranges on slow networks) can look like "hangs".
- **Heartbeat Thread**: Checks `self.last_activity` timestamp every 60s.
- **States**:
    - **Active**: Activity < 60s ago. No output.
    - **Busy**: Activity < 300s ago. Warning log.
    - **Silent**: Activity > 300s ago. 
        - Message: *"Nmap is still running; this is normal on slow or filtered hosts."*
        - **Action**: Do NOT abort. Deep scans can take 8-10 minutes on firewall-protected hosts.
- **Logs**: Check `~/.redaudit/logs/` for fine-grained debugging info.

## 9. Verification Script
Ensure your deployment is clean and uncorrupted.
```bash
bash redaudit_verify.sh
```
Checks:
- Binary paths.
- Python module availability (`cryptography`, `nmap`).
- Alias configuration.
- Optional tool presence.

## 10. FAQ
**Q: Why "Encryption missing" error?**
A: You likely skipped the dependency installation. Run `sudo apt install python3-cryptography`.

**Q: Can I scan over VPN?**
A: Yes, RedAudit detects VPN tun0/tap0 interfaces automatically.

**Q: Is it safe for production?**
A: Yes, if configured responsibly (Threads < 5, Rate Limit > 1s). Always have authorization.

**Q: Why minimal ports found?**
A: The target might be filtering SYN packets. RedAudit will attempt a Deep Scan automatically to try and bypass this.

## 11. Glossary
- **Deep Scan**: Automated fallback using aggressive Nmap flags to probe "quiet" hosts.
- **Fernet**: Symmetric encryption primitive ensuring 128-bit security and integrity.
- **Heartbeat**: Background monitoring thread ensuring process health.
- **PBKDF2**: *Password-Based Key Derivation Function 2*. Makes password cracking slow.
- **Ports Truncated**: Optimization where lists >50 ports are summarized to keep reports readable.
- **Rate Limit**: Artificial delay introduced to reduce network noise.
- **Salt**: Random data combined with password to create a unique encryption key.

## 12. Legal Notice
This tool is for **authorized security auditing only**. Usage without written consent of the network owner is illegal in strict liability jurisdictions. The authors accept no liability for damage or unauthorized use.

### License

RedAudit is licensed under the **GNU General Public License v3.0 (GPLv3)**.  
See the root [LICENSE](../LICENSE) file for details.
