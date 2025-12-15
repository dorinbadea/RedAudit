# RedAudit

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](README_ES.md)

RedAudit is a CLI tool for structured network auditing and hardening on Kali/Debian systems.

![Version](https://img.shields.io/badge/version-3.1.3-blue?style=flat-square)
![License](https://img.shields.io/badge/license-GPLv3-red?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
![CI/CD](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg?style=flat-square)

```text
 ____          _    _             _ _ _   
|  _ \ ___  __| |  / \  _   _  __| (_) |_ 
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_ 
|_| \_\___|\__,_/_/   \_\__,_|\__,_|_|\__|
                                      v3.1.3
        Interactive Network Audit Tool
```

## Overview

RedAudit automates the discovery, enumeration, and reporting phases of network security assessments. It is designed for use in controlled lab environments, defensive hardening workflows, and authorized offensive security exercises. By orchestrating standard industry tools into a coherent concurrent pipeline, it reduces manual overhead and ensures consistent output generation.

The tool bridges the gap between ad-hoc scanning and formal auditing, providing structured artifacts (JSON/TXT) that are ready for ingestion into reporting frameworks or SIEM analysis.

## Features

- **3-Phase Adaptive Deep Scan**: Intelligent escalation (TCP aggressive → Priority UDP → Full UDP identity) triggered by host ambiguity
- **Smart-Check False Positive Filtering**: 3-layer verification (Content-Type, size checks, magic byte validation) reduces Nikto noise by 90%
- **Network Topology Discovery**: Best-effort L2/L3 mapping (ARP/VLAN/LLDP + gateway/routes) for hidden network detection
- **CVE Intelligence**: NVD API 2.0 integration with CPE 2.3 matching, 7-day caching, and deterministic finding IDs
- **SIEM-Ready Exports**: Auto-generated JSONL flat files (findings, assets, summary) with ECS v8.11 compliance
- **Entity Resolution**: Multi-interface device consolidation via hostname/NetBIOS/mDNS fingerprinting
- **Persistent Defaults**: User preferences stored in `~/.redaudit/config.json` for workflow automation
- **Differential Analysis**: JSON report comparison engine to track network changes over time
- **IPv6 + Proxy Support**: Full dual-stack scanning with SOCKS5 pivoting capabilities
- **Report Encryption**: AES-128-CBC (Fernet) with PBKDF2-HMAC-SHA256 key derivation (480k iterations)
- **Rate Limiting with Jitter**: Configurable inter-host delay (±30% randomization) for IDS evasion
- **Bilingual Interface**: Complete English/Spanish localization

## Architecture

RedAudit operates as an orchestration layer, managing concurrent execution threads for network interaction and data processing. It implements a two-phase architecture: generic discovery followed by targeted deep scans.

| **Category** | **Tools** | **Purpose** |
|:---|:---|:---|
| **Core Scanner** | `nmap`, `python3-nmap` | TCP/UDP port scanning, service/version detection, OS fingerprinting. |
| **Web Recon** | `whatweb`, `curl`, `wget`, `nikto` | Analyzes HTTP headers, technologies, and vulnerabilities. |
| **Exploit Intel** | `searchsploit` | Automatic ExploitDB lookup for services with detected versions. |
| **CVE Intelligence** | NVD API | CVE correlation for detected service versions (v3.0). |
| **SSL/TLS Analysis** | `testssl.sh` | Deep SSL/TLS vulnerability scanning (Heartbleed, POODLE, weak ciphers). |
| **Traffic Capture** | `tcpdump`, `tshark` | Captures network packets for detailed protocol analysis. |
| **DNS/Whois** | `dig`, `whois` | Reverse DNS lookups and ownership information for public IPs. |
| **Diff Analysis** | Built-in | Compare JSON reports to track network changes over time (v3.0). |
| **Pivoting** | `proxychains` wrapper | SOCKS5 proxy support for internal network access (v3.0). |
| **Topology** | `arp-scan`, `ip route` | L2 discovery, VLAN detection, and gateway mapping (v3.1+). |
| **Orchestrator** | `concurrent.futures` (Python) | Manages thread pools for parallel host scanning. |
| **Encryption** | `python3-cryptography` | AES-128 encryption for sensitive audit reports. |

### System Overview

![System Overview](docs/images/system_overview_v3.png)

Deep scans are triggered selectively: web auditing modules launch only upon detection of HTTP/HTTPS services, and SSL inspection is reserved for encrypted ports.

### Project Structure

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
│   ├── nvd.py          # CVE correlation via NVD API
│   ├── diff.py         # Differential analysis module
│   ├── proxy.py        # SOCKS5 proxy support
│   ├── scanner_versions.py  # Tool version detection (v3.1)
│   ├── evidence_parser.py   # Observation extraction (v3.1)
│   ├── jsonl_exporter.py    # JSONL exports (v3.1)
│   ├── udp_probe.py     # Async UDP probing (v3.1.3)
│   └── topology.py      # Async topology discovery (v3.1+)
└── utils/              # Utilities
    ├── constants.py    # Configuration constants
    ├── i18n.py         # Internationalization
    └── config.py       # Persistent configuration
```

## Installation

RedAudit requires a Debian-based environment (Kali Linux recommended). `sudo` privileges are recommended for full functionality (raw sockets, OS detection, tcpdump). A limited non-root mode is available via `--allow-non-root`.

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

### Post-Install Verification

Verify installation integrity:

```bash
# 1. Check command is available
which redaudit  # Should return: /usr/local/bin/redaudit

# 2. Verify version
redaudit --version  # Should show: RedAudit v3.1.3

# 3. Check core dependencies
command -v nmap && command -v tcpdump && command -v python3  # All should succeed

# 4. Optional: Run verification script
bash redaudit_verify.sh  # Checks checksums, dependencies, and configuration
```

**Optional Configuration (v3.1.1):**

```bash
# Store NVD API key for CVE correlation (one-time setup)
redaudit  # Interactive mode will prompt for API key if --cve-lookup is used

# Set persistent defaults to avoid repeating flags
redaudit --target 192.168.1.0/24 --threads 8 --rate-limit 1 --save-defaults --yes
# Future runs will use these settings automatically
```

### Usage Examples

#### Basic Scanning

```bash
# 1. Quick host discovery (fast mode)
sudo redaudit --target 192.168.1.0/24 --mode fast --yes

# 2. Standard security audit
sudo redaudit --target 192.168.1.0/24 --mode normal --yes

# 3. Comprehensive audit with all checks
sudo redaudit --target 192.168.1.0/24 --mode full --yes

# 4. Multiple networks simultaneously
sudo redaudit --target "192.168.1.0/24,10.0.0.0/24,172.16.0.0/16" --mode normal --threads 8
```

#### Stealth & Performance

```bash
# 5. Stealthy scan with rate limiting and jitter
sudo redaudit --target 10.0.0.0/24 --mode normal --rate-limit 2 --threads 4 --yes

# 6. Fast scan with pre-scan optimization
sudo redaudit --target 192.168.0.0/16 --prescan --prescan-ports 1-1024 --threads 12 --yes

# 7. Custom UDP coverage for identity scanning
sudo redaudit --target 192.168.1.0/24 --mode full --udp-mode full --udp-ports 200 --yes
```

#### Encryption & Security

```bash
# 8. Encrypted reports (auto-generated password)
sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --yes

# 9. Encrypted reports (custom password)
sudo redaudit --target 192.168.1.0/24 --mode full --encrypt --encrypt-password "Str0ng!Pass2024" --yes
```

#### v3.0 Advanced Features

```bash
# 10. IPv6 network scanning
sudo redaudit --target "2001:db8::/64" --ipv6 --mode normal --yes

# 11. CVE correlation with NVD intelligence
sudo redaudit --target 192.168.1.0/24 --mode normal --cve-lookup --nvd-key YOUR_API_KEY --yes

# 12. Scan through SOCKS5 proxy (pivoting)
sudo redaudit --target 10.internal.0.0/24 --proxy socks5://pivot-host:1080 --mode normal --yes

# 13. Differential analysis (compare two scans)
redaudit --diff ~/reports/baseline_monday.json ~/reports/current_friday.json
```

#### v3.1 SIEM Integration

```bash
# 14. Generate SIEM-ready JSONL exports (no encryption)
sudo redaudit --target 192.168.1.0/24 --mode full --yes
# Outputs: findings.jsonl, assets.jsonl, summary.json alongside JSON report
```

#### v3.1.1 Topology & Persistence

```bash
# 15. Topology discovery only (network mapping)
sudo redaudit --target 192.168.1.0/24 --topology-only --yes

# 16. Full scan with topology context
sudo redaudit --target 192.168.1.0/24 --mode normal --topology --yes

# 17. Save your preferred settings as defaults
sudo redaudit --target 192.168.1.0/24 --mode normal --threads 8 \
  --rate-limit 1 --topology --udp-mode full --save-defaults --yes
# Future runs will reuse these settings automatically
```

#### Real-World Workflows

```bash
# 18. Weekly audit workflow
# Step 1: Baseline scan
sudo redaudit --target 192.168.0.0/16 --mode normal --yes
# Step 2: Weekly comparison
sudo redaudit --target 192.168.0.0/16 --mode normal --yes
redaudit --diff ~/Documents/RedAuditReports/RedAudit_BASELINE/redaudit_*.json \
              ~/Documents/RedAuditReports/RedAudit_LATEST/redaudit_*.json

# 19. Multi-VLAN enterprise network audit
sudo redaudit --target "10.10.0.0/16,10.20.0.0/16,10.30.0.0/16" \
  --mode normal --topology --threads 10 --rate-limit 0.5 --yes

# 20. Post-scan verification and export
sudo redaudit --target 192.168.1.0/24 --mode full --cve-lookup --yes
# Verify JSONL exports were generated
ls -lh ~/Documents/RedAuditReports/RedAudit_*/findings.jsonl
# Ingest into your SIEM
cat ~/Documents/RedAuditReports/RedAudit_*/findings.jsonl | your-siem-ingestion-tool
```

**Available CLI Options:**

- `--target, -t`: Target network(s) in CIDR notation (required for non-interactive)
- `--mode, -m`: Scan mode (fast/normal/full, default: normal)
- `--threads, -j`: Concurrent threads (1-16, default: 6)
- `--rate-limit`: Delay between hosts in seconds (default: 0)
- `--encrypt, -e`: Encrypt reports with password
- `--encrypt-password`: Custom password for encryption (optional, default: random generated)
- `--output, -o`: Output directory (default: ~/Documents/RedAuditReports)
- `--max-hosts`: Maximum discovered hosts to scan (default: all)
- `--no-vuln-scan`: Disable web vulnerability scanning
- `--no-txt-report`: Disable TXT report generation
- `--no-deep-scan`: Disable adaptive deep scan
- `--prescan`: Enable fast asyncio pre-scan before nmap
- `--prescan-ports`: Port range for pre-scan (default: 1-1024)
- `--prescan-timeout`: Pre-scan timeout in seconds (default: 0.5)
- `--udp-mode`: UDP scan mode: quick (default) or full
- `--udp-ports`: Top UDP ports count used in `--udp-mode full` (50-500, default: 100) **(v3.1+)**
- `--topology`: Enable topology discovery (ARP/VLAN/LLDP + gateway/routes) **(v3.1+)**
- `--no-topology`: Disable topology discovery (override persisted defaults) **(v3.1+)**
- `--topology-only`: Run topology discovery only (skip host scanning) **(v3.1+)**
- `--save-defaults`: Save current CLI settings as persistent defaults (`~/.redaudit/config.json`) **(v3.1+)**
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
3. **Phase 2b - Extended UDP identity**: Only in `full` mode if no identity found yet (`-O -sU --top-ports N`, configurable via `--udp-ports`)

**Deep Scan features:**

- **Concurrent PCAP Capture**: Traffic is captured during deep scans (not after)
- **Banner Grab Fallback**: Uses `--script banner,ssl-cert` for unidentified ports
- **Host Status Accuracy**: New status types (`up`, `filtered`, `no-response`, `down`)
- **Intelligent Skip**: Phases 2a/2b are skipped if MAC/OS is already detected

- **Trigger**: Automatic based on heuristics (few ports, suspicious services, etc.)
- **Output**: Full logs, MAC/Vendor data, and (when captured) PCAP metadata in `host.deep_scan.pcap_capture`

### UDP Taming

Faster UDP scanning without sacrificing detection quality:

- Uses `--top-ports N` (default: 100, configurable via `--udp-ports`) instead of full 65535 ports
- Strict `--host-timeout 300s` per host
- Reduced retries (`--max-retries 1`) for LAN efficiency
- **Result**: 50-80% faster UDP scans

### Secure Auto-Update

RedAudit can check for and install updates automatically:

- **Startup Check**: Prompts to check for updates when launching in interactive mode
- **Auto-Install**: Downloads and installs updates via `git clone`
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
- **60-300s silence**: Logs a **WARNING** that the tool may be busy.
- **>300s silence**: Logs a **WARNING** with message "The active tool is still running; this is normal for slow or filtered hosts."
- **Purpose**: Assures the operator that the tool is alive during long operations (e.g., deep scans, nikto, testssl).

## 10. Verification Script

Verify your environment integrity (checksums, dependencies, alias) at any time:

```bash
bash redaudit_verify.sh
```

*Useful after OS updates or git pulls.*

## 11. Glossary

### Infrastructure & Cryptography

- **Fernet**: Symmetric encryption standard using AES-128-CBC and HMAC-SHA256, providing authenticated encryption for report confidentiality.
- **PBKDF2**: Password-Based Key Derivation Function 2. Transforms user passwords into cryptographic keys through 480,000 iterations to resist brute-force attacks.
- **Salt**: Random 16-byte data added to password hashing to prevent rainbow table attacks, stored in `.salt` files alongside encrypted reports.
- **Thread Pool**: Concurrent worker collection managed by `ThreadPoolExecutor` for parallel host scanning (default: 6 threads, configurable via `-j`).
- **Heartbeat**: Background monitoring thread that checks scan progress every 30s and warns if tools are silent for >300s, indicating potential hangs.
- **Rate Limiting**: Configurable inter-host delay with ±30% jitter to evade IDS threshold detection (activated via `--rate-limit`).
- **ECS**: Elastic Common Schema v8.11 compatibility for SIEM integration with event typing, risk scoring (0-100), and observable hashing for deduplication.
- **Finding ID**: Deterministic SHA256 hash (`asset_id + scanner + port + signature + title`) for cross-scan correlation and deduplication.
- **CPE**: Common Platform Enumeration v2.3 format used for matching software versions against NVD CVE database.
- **JSONL**: JSON Lines format - one JSON object per line, optimized for streaming ingestion into SIEM/AI pipelines.

**Note**: For detailed explanations of scanning strategies (Deep Scan, Smart-Check, Topology Discovery, etc.), see the Features section above.

## 12. Troubleshooting

For comprehensive troubleshooting, see [docs/en/TROUBLESHOOTING.md](docs/en/TROUBLESHOOTING.md).

### Common Installation Issues

**1. "Permission denied" / Root privileges required**

- **Cause**: Running without `sudo` (nmap requires raw sockets)
- **Fix**: Prepend `sudo` to command, or use `--allow-non-root` for limited mode
- **Verify**: `id -u` should return 0 when running with sudo

**2. "nmap: command not found"**

- **Cause**: nmap not installed or not in PATH
- **Fix**: `sudo apt update && sudo apt install nmap`
- **Verify**: `which nmap` should show `/usr/bin/nmap`

**3. "ModuleNotFoundError: cryptography"**

- **Cause**: Python dependencies missing
- **Fix**: `sudo bash redaudit_install.sh` or `sudo apt install python3-cryptography python3-nmap python3-netifaces`

**4. Alias not working after installation**

- **Cause**: Shell configuration not reloaded
- **Fix**: Run `source ~/.zshrc` (Kali) or `source ~/.bashrc` (Debian/Ubuntu), or open new terminal

### Scanning Issues

**5. "Scan appears frozen" / Long pauses**

- **Cause**: Deep scan legitimately takes 90-150s per complex host
- **Check**: Look for `[deep]` marker in output - this is normal
- **Monitor**: Check `~/.redaudit/logs/` for heartbeat messages
- **Workaround**: Use `--no-deep-scan` or reduce `--threads` to 4

**6. "Too many hosts, scan never finishes"**

- **Cause**: Scanning large /16 networks without optimization
- **Fix**: Use `--prescan` for faster discovery, or `--max-hosts N` to limit scope
- **Example**: `sudo redaudit -t 192.168.0.0/16 --prescan --max-hosts 100 --yes`

**7. Heartbeat warnings in logs**

- **Cause**: Nikto/TestSSL running slowly on filtered hosts
- **Status**: Normal - tools are still running
- **Action**: Wait or reduce `--rate-limit` if too aggressive

### Encryption & Decryption

**8. "Decryption failed: Invalid token"**

- **Cause**: Wrong password or corrupted `.salt` file
- **Fix**: Verify password (case-sensitive), ensure `.salt` file exists in same directory
- **Check**: `.salt` file should be 16 bytes: `ls -lh *.salt`

**9. "Cryptography not available" warning**

- **Cause**: `python3-cryptography` package missing
- **Impact**: Encryption options will be disabled
- **Fix**: `sudo apt install python3-cryptography`

### Network & Connectivity

**10. IPv6 scanning not working**

- **Cause**: IPv6 disabled on system or nmap built without IPv6 support
- **Verify**: `ip -6 addr show` and `nmap -6 ::1`
- **Fix**: Enable IPv6 in `/etc/sysctl.conf` or use IPv4 targets

**11. NVD API rate limit errors**

- **Cause**: Using NVD API without key (limited to 5 requests/30s)
- **Fix**: Get free API key from <https://nvd.nist.gov/developers/request-an-api-key>
- **Usage**: `--nvd-key YOUR_KEY` or store in `~/.redaudit/config.json`

**12. Proxy connection failed**

- **Cause**: `proxychains` not installed or proxy unreachable
- **Fix**: `sudo apt install proxychains4` and test proxy: `curl --socks5 host:port http://example.com`
- **Format**: `--proxy socks5://host:port`

### Output & Reports

**13. JSONL exports not generated**

- **Cause**: Report encryption is enabled (JSONL only generated when encryption is off)
- **Fix**: Run without `--encrypt` flag to generate `findings.jsonl`, `assets.jsonl`, `summary.json`

**14. "Output directory not found"**

- **Cause**: Custom output path doesn't exist
- **Fix**: Create directory first: `mkdir -p /path/to/output` or let RedAudit use default (`~/Documents/RedAuditReports`)

### Performance Tuning

**15. Scans too slow on large networks**

- **Optimization 1**: Use `--prescan` for asyncio fast discovery
- **Optimization 2**: Increase `--threads` to 12-16 (but watch for network congestion)
- **Optimization 3**: Use `--mode fast` for quick inventory, then targeted `full` scans
- **Example**: `sudo redaudit -t 10.0.0.0/16 --prescan --threads 12 --mode fast --yes`

**16. High CPU/memory usage**

- **Cause**: Too many concurrent threads or deep scans on many hosts
- **Fix**: Reduce `--threads` to 4-6, use `--no-deep-scan`, or add `--rate-limit 1`

**17. Network congestion / IDS alerts**

- **Cause**: Aggressive scanning triggering security systems
- **Fix**: Add `--rate-limit 2` (with ±30% jitter) and reduce `--threads` to 4
- **Stealth mode**: `sudo redaudit -t TARGET --mode normal --rate-limit 3 --threads 2 --yes`

## 13. Changelog

### v3.1 Features

- **JSONL Exports**: Auto-generated `findings.jsonl`, `assets.jsonl`, `summary.json` for SIEM/AI pipelines (when report encryption is disabled)
- **Finding IDs**: Deterministic hashes for cross-scan finding correlation
- **Category Classification**: surface/misconfig/crypto/auth/info-leak/vuln
- **Normalized Severity**: CVSS-like 0-10 scale with preserved tool severity
- **Parsed Observations**: Structured extraction from Nikto/TestSSL output
- **Scanner Versions**: Tool version detection for provenance tracking
- **Topology Discovery (best-effort)**: Optional ARP/VLAN/LLDP + gateway/routes (`--topology`, `--topology-only`)
- **Persistent Defaults**: `--save-defaults` stores common settings in `~/.redaudit/config.json`
- **Configurable UDP Coverage**: `--udp-ports` to tune full UDP identity scan coverage

### v3.0 Features

- **IPv6 Support**: Full scanning capabilities for IPv6 networks
- **CVE Correlation (NVD)**: Deep vulnerability intelligence via NIST NVD API
- **Differential Analysis**: Compare scan reports to detect network changes (`--diff`)
- **Proxy Chains (SOCKS5)**: Network pivoting support via proxychains
- **Magic Byte Validation**: Enhanced false positive detection

### v2.9 Improvements

- **Smart-Check**: Automatic Nikto false positive filtering
- **UDP Taming**: 50-80% faster scans with optimized strategy
- **Entity Resolution**: Multi-interface host consolidation
- **SIEM Professional**: ECS v8.11 compliance, severity scoring

For detailed changelog, see [CHANGELOG.md](CHANGELOG.md)

## 14. Contributing

We welcome contributions! Please see [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details.

## 15. License

RedAudit is released under the **GNU General Public License v3.0 (GPLv3)**.  
See the [LICENSE](LICENSE) file for the full text and terms.

## 16. Internals & Glossary (Why RedAudit behaves this way)

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

## 17. Legal Notice

**RedAudit** is a security tool for **authorized auditing only**.
Scanning networks without permission is illegal. By using this tool, you accept full responsibility for your actions and agree to use it only on systems you own or have explicit authorization to test.

---
[Full Documentation](docs/README.md) | [Report Schema](docs/en/REPORT_SCHEMA.md) | [Security Specs](docs/en/SECURITY.md)
