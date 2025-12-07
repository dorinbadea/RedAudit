<div align="center">
  <img src="assets/header.png" alt="RedAudit Banner" width="100%">

  <br>

  [ 🇬🇧 English ](README.md) | [ 🇪🇸 Español ](README_ES.md)

  <br>

  [![Version](https://img.shields.io/badge/version-2.5-blue.svg)](https://github.com/dorinbadea/RedAudit)
  ![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
  ![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
</div>

<br>

# 🦅 RedAudit v2.5

## 1. 📋 Overview
**RedAudit** is an interactive, automated network auditing tool designed for **Kali Linux** and Debian-based systems. It streamlines the reconnaissance process by combining network discovery, port scanning, and vulnerability assessment into a single, cohesive CLI workflow.

Unlike simple wrapper scripts, RedAudit manages concurrency, data aggregation, and reporting (JSON/TXT) with Python-based logic, offering professional-grade reliability and audit trails.

## 2. ✨ Features
- **Interactive & Non-Interactive CLI**: Guided menu or full command-line arguments for automation
- **Smart Discovery**: Auto-detects local interfaces and subnets using `ip` commands
- **Multi-Mode Scanning**:
    - **FAST**: ICMP ping sweep (`-sn`) for quick live host detection
    - **NORMAL**: Top ports + Service Versioning (`-sV`)
    - **FULL**: All ports, OS detection (`-O`), Scripts (`-sC`), and Web Vuln scans
- **Adaptive Deep Scan**: Intelligent 2-phase engine (TCP Aggressive → UDP/OS Fallback) that maximizes speed and data
- **Vendor/MAC Detection**: Automatically extracts hardware info even from partial scans
- **Traffic Analysis**: Optional micro-captures (`tcpdump`) for active analysis of target behavior
- **Web Recon**: Integrates `whatweb`, `nikto`, `curl`, and `openssl` for web-facing services
- **Resilience**: Background heartbeat monitor prevents silent freezes during long scans
- **Automation Ready**: Full CLI support for scripting and CI/CD integration

## 3. 🔒 Security Features (Enhanced in v2.5)
RedAudit v2.5 introduces enterprise-grade security hardening:
- **Hardened Input Sanitization**: All user inputs validated for type, length, and format
  - Type validation (only `str` accepted)
  - Length limits (1024 chars for IPs/hostnames, 50 for CIDR)
  - Automatic whitespace stripping
  - Strict regex validation (`^[a-zA-Z0-9\.\-\/]+$`)
  - No shell injection (uses `subprocess.run` with lists)
- **Encrypted Reports**: Optional **AES-128 (Fernet)** encryption with PBKDF2-HMAC-SHA256 (480,000 iterations)
- **Secure File Permissions**: All reports use 0o600 permissions (owner read/write only)
- **Graceful Cryptography Handling**: Clear warnings if encryption unavailable, no password prompts
- **Thread Safety**: `ThreadPoolExecutor` with proper locking mechanisms for concurrent I/O
- **Rate Limiting**: Configurable `time.sleep()` delays to mitigate network flooding and IDS detection
- **Audit Logging**: Comprehensive, rotating logs (max 10MB, 5 backups) stored in `~/.redaudit/logs/`

[→ Full Security Documentation](docs/SECURITY.md)

## 4. 📦 Requirements & Dependencies
Designed for **Kali Linux**, **Debian**, or **Ubuntu**.
Requires `root` or `sudo` privileges for Nmap OS detection and raw packet capture.

**Core (Required):**
- `nmap` (Network Mapper)
- `python3-nmap` (Python bindings)
- `python3-cryptography` (For encryption)

**Recommended (Enrichment):**
- `whatweb`, `nikto` (Web scanning)
- `tcpdump`, `tshark` (Traffic capture)
- `curl`, `wget`, `openssl` (HTTP/TLS analysis)
- `bind9-dnsutils` (for `dig`)

## 5. 🏗️ Installation
The installer handles dependencies and setup automatically.

```bash
# 1. Clone Repository
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit

# 2. Run Installer (Interactive)
sudo bash redaudit_install.sh

# 3. Reload Shell (to activate alias)
source ~/.bashrc  # or ~/.zshrc
```
*Note: Use `sudo bash redaudit_install.sh -y` for non-interactive installation.*

## 6. 🚀 Quick Start

### Interactive Mode
Launch the tool from any terminal:
```bash
redaudit
```
You will be guided through:
1.  **Target Selection**: Pick a local subnet or enter a custom CIDR (e.g., `10.0.0.0/24`)
2.  **Scan Mode**: Select FAST, NORMAL, or FULL
3.  **Options**: Configure threads, rate limits, and encryption
4.  **Authorization**: Confirm permission to scan

### Non-Interactive Mode (NEW in v2.5)
For automation and scripting:
```bash
# Basic scan
sudo redaudit --target 192.168.1.0/24 --mode normal

# Full scan with encryption
sudo redaudit --target 10.0.0.0/24 --mode full --threads 8 --encrypt --output /tmp/reports

# Multiple targets
sudo redaudit --target "192.168.1.0/24,10.0.0.0/24" --mode normal --threads 6

    # Skip legal warning (for automation)
    sudo redaudit --target 192.168.1.0/24 --mode fast --yes

    # With encryption (random password generated)
    sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --yes

    # With encryption (custom password)
    sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --encrypt-password "MySecurePassword123" --yes
```

**Available CLI Options:**
- `--target, -t`: Target network(s) in CIDR notation (required for non-interactive)
- `--mode, -m`: Scan mode (fast/normal/full, default: normal)
- `--threads, -j`: Concurrent threads (1-16, default: 6)
- `--rate-limit`: Delay between hosts in seconds (default: 0)
- `--encrypt, -e`: Encrypt reports with password
- `--output, -o`: Output directory (default: ~/RedAuditReports)
- `--max-hosts`: Maximum hosts to scan (default: all)
- `--no-vuln-scan`: Disable web vulnerability scanning
- `--no-txt-report`: Disable TXT report generation
- `--no-deep-scan`: Disable adaptive deep scan
- `--yes, -y`: Skip legal warning (use with caution)
- `--lang`: Language (en/es)

See `redaudit --help` for full details.

## 7. ⚙️ Configuration & Internal Parameters

### Concurrency (Threads)
RedAudit uses Python's `ThreadPoolExecutor` to scan multiple hosts simultaneously.
- **Parameter**: `threads` (Default: 6).
- **Range**: 1–16.
- **Behavior**: These are *threads*, not processes. They share memory but execute Nmap instances independently.
    - **Higher (10-16)**: Faster scan, but higher network noise and CPU load. Risk of congestion.
    - **Lower (1-4)**: Slower, stealthier, kinder to legacy networks.

### Rate Limiting (Stealth)
Controlled by the `rate_limit_delay` parameter.
- **Mechanism**: Introduces a `time.sleep(N)` *before* each host scan task starts.
- **Settings**:
    - **0s**: Max speed. Best for CTFs or labs.
    - **1-5s**: Balanced. Recommended for internal audits to avoid simple rate-limiter triggers.
    - **>5s**: Paranoid/Conservative. Use for sensitive production environments.

### Adaptive Deep Scan (v2.5)
RedAudit applies a smart 2-phase scan to "silent" or complex hosts:
1.  **Phase 1**: Aggressive TCP (`-A -p- -sV -Pn`).
2.  **Phase 2**: If Phase 1 yields no MAC/OS info, it launches OS+UDP detection (`-O -sSU`).
- **Trigger**: Automatic.
- **Benefit**: Saves time by skipping Phase 2 if the host is already identified.
- **Output**: Full logs and MAC/Vendor data in `host.deep_scan`.

## 8. 🔐 Reports, Encryption & Decryption
Reports are saved to `~/RedAuditReports` (default) with timestamps.

### Encryption (`.enc`)
If you check **"Encrypt reports?"** during setup:
1.  A random 16-byte salt is generated.
2.  Your password derives a 32-byte key via **PBKDF2HMAC-SHA256** (480,000 iterations).
3.  Files are encrypted using **Fernet (AES-128-CBC)**.
    - `report.json` → `report.json.enc`
    - `report.txt` → `report.txt.enc`
    - A `.salt` file is saved alongside.

### Decryption
To read your reports, you **must** have the `.salt` file and recall your password.
```bash
python3 redaudit_decrypt.py /path/to/report_NAME.json.enc
```
*The script automatically locates the corresponding `.salt` file.*

## 9. 💓 Logging & Heartbeat

### Application Logs
Debug and audit logs are stored in `~/.redaudit/logs/`.
- **Rotation**: Keeps last 5 logs, max 10MB each.
- **Content**: Tracks user PID, command arguments, and exceptions.

### Heartbeat Monitor
A background `threading.Thread` monitors the scan state every 30 seconds.
- **<60s silence**: Normal (no output).
- **60-300s silence**: Logs a **WARNING** that Nmap might be busy.
- **>300s silence**: Logs a **WARNING** with message "Nmap is still running; this is normal on slow or filtered hosts."
- **Purpose**: Assures the operator that the tool is alive during long Nmap operations (e.g., `-p-` scans).

## 10. ✅ Verification Script
Verify your environment integrity (checksums, dependencies, alias) at any time:
```bash
bash redaudit_verify.sh
```
*Useful after OS updates or git pulls.*

## 11. 📚 Glossary
- **Fernet**: Symmetric encryption standard using AES-128 and HMAC-SHA256.
- **Heartbeat**: Background task ensuring the main process is responsive.
- **Deep Scan**: Automated fallback scan (`-A`) triggered when a host returns limited data.
- **PBKDF2**: Key derivation function making brute-force attacks expensive (configured to 480k iterations).
- **Salt**: Random data added to password hashing to prevent rainbow table attacks. stored in `.salt` files.
- **Thread Pool**: Collection of worker threads that execute tasks (host scans) concurrently.

## 12. 🛠️ Troubleshooting
See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for detailed fixes.
- **"Permission denied"**: Ensure you run with `sudo`.
- **"Cryptography missing"**: Run `sudo apt install python3-cryptography`.
- **"Scan frozen"**: Check `~/.redaudit/logs/` or reduce `rate_limit_delay`.

## 13. ⚖️ Legal Notice
**RedAudit** is a security tool for **authorized auditing only**.
Scanning networks without permission is illegal. By using this tool, you accept full responsibility for your actions and agree to use it only on systems you own or have explicit authorization to test.

## 14. 📝 Changelog (v2.5 Summary)
- **Security**: Hardened input sanitization with type/length validation, secure file permissions (0o600)
- **Automation**: Full non-interactive CLI mode for scripting and CI/CD integration
- **Testing**: Comprehensive integration and encryption test suites
- **Robustness**: Improved cryptography handling with graceful degradation
- **Documentation**: Complete documentation updates in English and Spanish

For detailed changelog, see [CHANGELOG.md](CHANGELOG.md)

## 15. ⚖️ License

RedAudit is released under the **GNU General Public License v3.0 (GPLv3)**.  
See the [LICENSE](LICENSE) file for the full text and terms.

## 16. 🧠 Internals & Glossary (Why RedAudit behaves this way)

### Thread pool (`threads`)
RedAudit uses a thread pool to scan multiple hosts in parallel.  
The `threads` setting controls how many hosts are scanned concurrently:
- Low (2–4): slower but stealthier and less noisy.
- Medium (default 6): balanced for most environments.
- High (10–16): faster, but may create more noise and timeouts.

### Rate limiting
RedAudit can insert a small delay between host scans.  
This trades raw speed for stability and stealth during long operations.

### Heartbeat & watchdog
During long scans, RedAudit prints heartbeat messages if no output appears for a while.  
This helps distinguish a “silent but healthy” scan from a real freeze.

### Encrypted reports
Reports can be encrypted with a user password.  
Keys are derived with PBKDF2-HMAC-SHA256 (480k iterations) and a separate `.salt` file, so decryption is possible later with `redaudit_decrypt.py`.

---
[Full Documentation](docs/) | [Report Schema](docs/REPORT_SCHEMA.md) | [Security Specs](docs/SECURITY.md)