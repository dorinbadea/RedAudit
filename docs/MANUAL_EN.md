# RedAudit User Manual

**Version**: 2.3
**Date**: 2025-05-20
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
Run `redaudit` to start the interactive wizard.

**Example Session:**
```text
? Select network: 192.168.1.0/24
? Select scan mode: NORMAL
? Enter number of threads [1-16]: 6
? Enable Web Vulnerability scans? [y/N]: y
? Deep-scan unusual infrastructure hosts when suspicious ports/services are found? [Y/n]: y
? Encrypt reports with password? [y/N]: y
```

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
RedAudit treats report data as sensitive sensitive material.
- **Standard**: **Fernet** (Specification compliant).
    - **Cipher**: AES-128 in CBC mode.
    - **Signing**: HMAC-SHA256.
    - **Validation**: Timestamp-aware token (TTL ignored by default).
- **Key Derivation**:
    - **Algorithm**: PBKDF2HMAC (SHA-256).
    - **Iterations**: 480,000 (exceeds OWASP recommendation of 310,000).
    - **Salt**: 16 random bytes, stored in `.salt` file.

## 6. Scan Logic & Phases
1.  **Discovery**: ICMP Echo (`-PE`) + ARP (`-PR`) sweep to map live hosts.
2.  **Enumeration**: Parallel Nmap scans based on mode.
3.  **Automatic Deep Scan**:
    - **Triggers**:
        1.  **Limited Data**: The host is alive but returns minimal or confusing data.
        2.  **Infrastructure Heuristic**: The host has few open ports and runs services typical of infrastructure (e.g., VPN, proxy, Nagios, SNMP), *if enabled* in setup.
    - **Action**: Launches aggressive flags (`-A -p-`) and UDP (`-sU`) to penetrate local firewalls or find non-standard services.
    - **Result**: Data is stored in `host.deep_scan`, including command output.

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
    - **Frozen**: Activity > 300s ago. Warning on console ("Zombie scan?").
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
