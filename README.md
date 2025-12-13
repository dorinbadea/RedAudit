# RedAudit

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](README_ES.md)

RedAudit is a CLI tool for structured network auditing and hardening on Kali/Debian systems.

![Version](https://img.shields.io/badge/version-3.0.1-blue?style=flat-square)
![License](https://img.shields.io/badge/license-GPLv3-red?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
![CI/CD](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/dorinbadea/81671a8fffccee81ca270f14d094e5a1/raw/redaudit-tests.json&style=flat-square&label=CI%2FCD)

```text
 ____          _    _             _ _ _   
|  _ \ ___  __| |  / \  _   _  __| (_) |_ 
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_ 
|_| \_\___|\__,_/_/   \_\__,_|\__,_|_|\__|
                                     v3.0.1
        Interactive Network Audit Tool
```

## Overview

RedAudit automates the discovery, enumeration, and reporting phases of network security assessments. It is designed for use in controlled lab environments, defensive hardening workflows, and authorized offensive security exercises. By orchestrating standard industry tools into a coherent concurrent pipeline, it reduces manual overhead and ensures consistent output generation.

The tool bridges the gap between ad-hoc scanning and formal auditing, providing structured artifacts (JSON/TXT) that are ready for ingestion into reporting frameworks or SIEM analysis.

## Architecture

RedAudit operates as an orchestration layer, managing concurrent execution threads for network interaction and data processing. It implements a two-phase architecture: generic discovery followed by targeted deep scans.

| **Category** | **Tools** | **Purpose** |
|:---|:---|:---|
| **Core Scanner** | `nmap`, `python3-nmap` | TCP/UDP port scanning, service/version detection, OS fingerprinting. |
| **Web Recon** | `whatweb`, `curl`, `wget`, `nikto` | Analyzes HTTP headers, technologies, and vulnerabilities. |
| **Exploit Intel** | `searchsploit` | Automatic ExploitDB lookup for services with detected versions. |
| **SSL/TLS Analysis** | `testssl.sh` | Deep SSL/TLS vulnerability scanning (Heartbleed, POODLE, weak ciphers). |
| **Traffic Capture** | `tcpdump`, `tshark` | Captures network packets for detailed protocol analysis. |
| **DNS/Whois** | `dig`, `whois` | Reverse DNS lookups and ownership information for public IPs. |
| **Orchestrator** | `concurrent.futures` (Python) | Manages thread pools for parallel host scanning. |
| **Encryption** | `python3-cryptography` | AES-128 encryption for sensitive audit reports. |

### System Overview

![System Overview](docs/images/system_overview_v3.png)

Deep scans are triggered selectively: web auditing modules launch only upon detection of HTTP/HTTPS services, and SSL inspection is reserved for encrypted ports.

## Installation

RedAudit requires a Debian-based environment (Kali Linux recommended) and `sudo` privileges for raw socket access.

```bash
# 1. Clone the repository
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit

# 2. Run the installer (handles dependencies and aliases)
sudo bash redaudit_install.sh
```

### Activating the Alias

After installation, you need to reload your shell configuration to use the `redaudit` command:

| Distribution | Default Shell | Command |
|:---|:---|:---|
| **Kali Linux** (2020.3+) | Zsh | `source ~/.zshrc` |
| **Debian / Ubuntu / Parrot** | Bash | `source ~/.bashrc` |

**Or simply open a new terminal window.**

> **Why two shells?** Kali Linux switched from Bash to Zsh in 2020 for enhanced features and customization. Most other Debian-based distros still use Bash as default. The installer automatically detects your shell and configures the correct file.

### Usage Examples

```bash
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
- `--encrypt-password`: Custom password for encryption (optional, default: random generated)
- `--output, -o`: Output directory (default: ~/Documents/RedAuditReports)
- `--max-hosts`: Maximum hosts to scan (default: all)
- `--no-vuln-scan`: Disable web vulnerability scanning
- `--no-txt-report`: Disable TXT report generation
- `--no-deep-scan`: Disable adaptive deep scan
- `--prescan`: Enable fast asyncio pre-scan before nmap
- `--prescan-ports`: Port range for pre-scan (default: 1-1024)
- `--prescan-timeout`: Pre-scan timeout in seconds (default: 0.5)
- `--udp-mode`: UDP scan mode: quick (default) or full
- `--skip-update-check`: Skip update check at startup
- `--yes, -y`: Skip legal warning (use with caution)
- `--lang`: Language (en/es)
- `--ipv6`: Enable IPv6-only scanning mode **(v3.0)**
- `--proxy URL`: SOCKS5 proxy for pivoting (socks5://host:port) **(v3.0)**
- `--diff OLD NEW`: Compare two JSON reports and show changes **(v3.0)**
- `--cve-lookup`: Enable CVE correlation via NVD API **(v3.0)**
- `--nvd-key KEY`: NVD API key for faster rate limits **(v3.0)**

See `redaudit --help` for full details.

## Configuration & Internal Parameters

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

### Adaptive Deep Scan

RedAudit applies a smart 3-phase adaptive scan to maximize information gathering:

1. **Phase 1 - Aggressive TCP**: Full port scan with version detection (`-A -p- -sV -Pn`)
2. **Phase 2a - Priority UDP**: Quick scan of 17 common UDP ports (DNS, DHCP, SNMP, NetBIOS)
3. **Phase 2b - Full UDP**: Only in `full` mode if no identity found yet (`-O -sSU -p-`)

**Deep Scan features:**

- **Concurrent PCAP Capture**: Traffic is captured during the scan (not after)
- **Banner Grab Fallback**: Uses `--script banner,ssl-cert` for unidentified ports
- **Host Status Accuracy**: New status types (`up`, `filtered`, `no-response`, `down`)
- **Intelligent Skip**: Phases 2a/2b are skipped if MAC/OS is already detected

- **Trigger**: Automatic based on heuristics (few ports, suspicious services, etc.)
- **Output**: Full logs, MAC/Vendor data, and PCAP in `host.deep_scan`

### UDP Taming

Faster UDP scanning without sacrificing detection quality:

- Uses `--top-ports 100` instead of full 65535 ports
- Strict `--host-timeout 300s` per host
- Reduced retries (`--max-retries 1`) for LAN efficiency
- **Result**: 50-80% faster UDP scans

## Modular Architecture

RedAudit is organized as a modular Python package:

```text
redaudit/
├── core/               # Core functionality
│   ├── auditor.py      # Main orchestrator class
│   ├── prescan.py      # Asyncio fast port discovery
│   ├── scanner.py      # Nmap scanning logic + IPv6 support
│   ├── crypto.py       # AES-128 encryption/decryption
│   ├── network.py      # Interface detection (IPv4/IPv6)
│   ├── reporter.py     # JSON/TXT + SIEM output
│   ├── updater.py      # Secure auto-update (git clone)
│   ├── verify_vuln.py  # Smart-Check false positive filtering
│   ├── entity_resolver.py  # Multi-interface host grouping
│   ├── siem.py         # Professional SIEM integration
│   ├── nvd.py          # CVE correlation via NVD API (v3.0)
│   ├── diff.py         # Differential analysis module (v3.0)
│   └── proxy.py        # SOCKS5 proxy support (v3.0)
└── utils/              # Utilities
    ├── constants.py    # Configuration constants
    ├── i18n.py         # Internationalization
    └── config.py       # Persistent configuration (v3.0.1)
```

### Secure Auto-Update

RedAudit can check for and install updates automatically:

- **Startup Check**: Prompts to check for updates when launching in interactive mode
- **Auto-Install**: Downloads and installs updates via `git pull`
- **Auto-Restart**: Automatically restarts with new code using `os.execv()`
- **Skip Flag**: Use `--skip-update-check` to disable update checking

**Alternative invocation:**

```bash
python -m redaudit --help
```

## 8. Reports, Encryption & Decryption

Reports are saved to `~/Documents/RedAuditReports` (default) with timestamps.

### Encryption (`.enc`)

If you check **"Encrypt reports?"** during setup:

1. A random 16-byte salt is generated.
2. Your password derives a 32-byte key via **PBKDF2HMAC-SHA256** (480,000 iterations).
3. Files are encrypted using **Fernet (AES-128-CBC)**.
    - `report.json` → `report.json.enc`
    - `report.txt` → `report.txt.enc`
    - A `.salt` file is saved alongside.

### Decryption

To read your reports, you **must** have the `.salt` file and recall your password.

```bash
python3 redaudit_decrypt.py /path/to/report_NAME.json.enc
```

*The script automatically locates the corresponding `.salt` file.*

## 9. Logging & Heartbeat

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

## 10. Verification Script

Verify your environment integrity (checksums, dependencies, alias) at any time:

```bash
bash redaudit_verify.sh
```

*Useful after OS updates or git pulls.*

## 11. Glossary

- **Fernet**: Symmetric encryption standard using AES-128 and HMAC-SHA256.
- **Heartbeat**: Background task ensuring the main process is responsive.
- **Deep Scan**: Automated fallback scan (`-A`) triggered when a host returns limited data.
- **PBKDF2**: Key derivation function making brute-force attacks expensive (configured to 480k iterations).
- **Salt**: Random data added to password hashing to prevent rainbow table attacks. stored in `.salt` files.
- **Thread Pool**: Collection of worker threads that execute tasks (host scans) concurrently.

## 12. Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for detailed fixes.

- **"Permission denied"**: Ensure you run with `sudo`.
- **"Cryptography missing"**: Run `sudo apt install python3-cryptography`.
- **"Scan frozen"**: Check `~/.redaudit/logs/` or reduce `rate_limit_delay`.

## 13. Changelog (v3.0.0)

### v3.0 Features

- **IPv6 Support**: Full scanning capabilities for IPv6 networks with automatic `-6` flag
- **CVE Correlation (NVD)**: Deep vulnerability intelligence via NIST NVD API with 7-day cache
- **Differential Analysis**: Compare two scan reports to detect network changes (`--diff`)
- **Proxy Chains (SOCKS5)**: Network pivoting support via proxychains wrapper
- **Magic Byte Validation**: Enhanced false positive detection with file signature verification
- **Enhanced Auto-Update**: Git clone approach with verification and home folder copy

### v2.9 Improvements

- **Smart-Check**: Automatic Nikto false positive filtering via Content-Type validation
- **UDP Taming**: 50-80% faster scans with `--top-ports 100` and strict timeouts
- **Entity Resolution**: Multi-interface host consolidation (`unified_assets` array)
- **SIEM Professional**: ECS v8.11 compliance, severity scoring, risk scores, auto-tags

### Core Features

- **Adaptive Deep Scan**: 3-phase strategy (TCP aggressive → Priority UDP → Full UDP)
- **Concurrent PCAP**: Traffic captured during scans, not after
- **Pre-scan Engine**: Fast asyncio port discovery before nmap
- **Exploit Intelligence**: SearchSploit integration for version-based lookups
- **SSL/TLS Analysis**: TestSSL.sh deep vulnerability scanning

For detailed changelog, see [CHANGELOG.md](CHANGELOG.md)

## 14. License

RedAudit is released under the **GNU General Public License v3.0 (GPLv3)**.  
See the [LICENSE](LICENSE) file for the full text and terms.

## 15. Internals & Glossary (Why RedAudit behaves this way)

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
This helps distinguish a "silent but healthy" scan from a real freeze.

### Encrypted reports

Reports can be encrypted with a user password.  
Keys are derived with PBKDF2-HMAC-SHA256 (480k iterations) and a separate `.salt` file, so decryption is possible later with `redaudit_decrypt.py`.

## 16. Legal Notice

**RedAudit** is a security tool for **authorized auditing only**.
Scanning networks without permission is illegal. By using this tool, you accept full responsibility for your actions and agree to use it only on systems you own or have explicit authorization to test.

---
[Full Documentation](docs/) | [Report Schema](docs/REPORT_SCHEMA.md) | [Security Specs](docs/SECURITY.md)
