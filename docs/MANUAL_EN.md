# RedAudit v2.6 User Manual

[![Ver en español](https://img.shields.io/badge/Ver%20en%20español-red?style=flat-square)](MANUAL_ES.md)

**Version**: 2.6
**Target Audience**: Security Analysts, Systems Administrators
**License**: GPLv3

## 1. Introduction

This manual provides comprehensive documentation for the operation and configuration of RedAudit. It covers deep technical aspects of the scanning engine, encryption mechanisms, and report handling.

## 2. Installation and Setup

Ensure the host system meets the following requirements:

- **OS**: Kali Linux, Debian, Ubuntu, Parrot OS.
- **Python**: v3.8+.
- **Privileges**: Root/Sudo (mandatory for raw socket access).

### Installation

Execute the installer script to automatically resolve dependencies (nmap, python-nmap, cryptography) and configure the system alias.

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### Shell Configuration

After installation, activate the alias:

| Distribution | Default Shell | Activation Command |
|:---|:---|:---|
| **Kali Linux** (2020.3+) | Zsh | `source ~/.zshrc` |
| **Debian / Ubuntu / Parrot** | Bash | `source ~/.bashrc` |

> **Note**: Kali uses Zsh by default since 2020. The installer auto-detects your shell.

## 3. Configuration

RedAudit prioritizes runtime configuration via CLI arguments over static config files to facilitate automation and stateless execution in containerized environments.

### Concurrency Control

The tool uses `concurrent.futures.ThreadPoolExecutor` to parallelize host operations. The default thread count is calculated as `cpu_count * 5`.

- **High Concurrency**: Use `--threads 20` for fast networks.
- **Low Concurrency**: Use `--threads 2` for unstable or metered connections.

## Modular Architecture (v2.6)

Starting with v2.6, RedAudit is organized as a Python package:

| Module | Purpose |
|:---|:---|
| `redaudit/core/auditor.py` | Main orchestrator class |
| `redaudit/core/scanner.py` | Scanning logic, sanitization |
| `redaudit/core/crypto.py` | Encryption (PBKDF2, Fernet) |
| `redaudit/core/network.py` | Network interface detection |
| `redaudit/core/reporter.py` | Report generation (JSON/TXT) |
| `redaudit/utils/constants.py` | Named configuration constants |
| `redaudit/utils/i18n.py` | Internationalization |

**Alternative invocation:**

```bash
python -m redaudit --help
```

### Rate Limiting

    - **Signing**: HMAC-SHA256.
    - **Validation**: Timestamp-aware token (TTL ignored by default).

- **Key Derivation**:
  - **Algorithm**: PBKDF2HMAC (SHA-256).
  - **Iterations**: 480,000 (exceeds OWASP recommendation of 310,000).
  - **Salt**: 16 random bytes, stored in `.salt` file.
- **Graceful Degradation** (v2.5): If `python3-cryptography` is unavailable, encryption is automatically disabled with clear warnings. No password prompts are shown.
- **File Permissions** (v2.5): All reports (encrypted and plain) use secure permissions (0o600 - owner read/write only).

## 6. Scan Logic & Phases

1. **Discovery**: ICMP Echo (`-PE`) + ARP (`-PR`) sweep to map live hosts.
2. **Enumeration**: Parallel Nmap scans based on mode.
3. **Adaptive Deep Scan (Automatic)**:
    - **Triggers**: Auto-triggered if a host:
        - Has more than 8 open ports
        - Has suspicious services (socks, proxy, vpn, tor, nagios, etc.)
        - Has 3 or fewer open ports
        - Has open ports but no version information detected
    - **Strategy (2-Phases)**:
        1. **Phase 1**: `nmap -A -sV -Pn -p- --open --version-intensity 9` (TCP Aggressive).
            - *Check*: If MAC/OS is found, stop here and skip Phase 2.
        2. **Phase 2**: `nmap -O -sSU -Pn -p- --max-retries 2` (UDP + OS fallback, only if Phase 1 yielded no identity).
    - **Result**: Data is stored in `host.deep_scan`, including `mac_address`, `vendor`, and `phase2_skipped` flag.

4. **Traffic Capture**:
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
