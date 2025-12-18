# RedAudit

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](README_ES.md)

![Version](https://img.shields.io/github/v/tag/dorinbadea/RedAudit?sort=semver&style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-GPLv3-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
![CI/CD](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg?style=flat-square)

```text
 ____          _    _             _ _ _
|  _ \ ___  __| |  / \  _   _  __| (_) |_
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_
|_| \_\___|__,_/_/   \_\__,_|\__,_|_|\__|
```

## What is RedAudit?

RedAudit is a network auditing framework that orchestrates industry-standard security tools (nmap, nikto, testssl, nuclei) into a concurrent pipeline. It automates discovery-to-report workflows, producing structured JSON/HTML/JSONL artifacts suitable for SIEM ingestion or compliance reporting.

**Use cases**: Defensive hardening, penetration test scoping, change tracking between assessments.

**Key differentiator**: Adaptive multi-phase scanning with automatic escalation—not just parallel execution of tools.

---

## Quick Start

```bash
# Install
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh

# Run your first scan
sudo redaudit --target 192.168.1.0/24 --mode normal --yes
```

For interactive mode (wizard-guided setup), simply run:

```bash
sudo redaudit
```

---

## Core Capabilities

### Scanning & Discovery

| Capability | Description |
|:---|:---|
| **Adaptive Deep Scan** | 3-phase escalation (TCP → Priority UDP → Full UDP) based on host identity ambiguity |
| **HyperScan** | Async batch TCP + UDP IoT broadcast + aggressive ARP for ultra-fast triage |
| **Topology Discovery** | L2/L3 mapping (ARP/VLAN/LLDP + gateway/routes) for hidden network detection |
| **Network Discovery** | Broadcast protocols (DHCP/NetBIOS/mDNS/UPNP) for guest network detection |
| **Stealth Mode** | T1 paranoid timing, single-thread, 5s+ delays for enterprise IDS evasion |

### Intelligence & Correlation

| Capability | Description |
|:---|:---|
| **CVE Correlation** | NVD API 2.0 with CPE 2.3 matching and 7-day cache |
| **Exploit Lookup** | Automatic ExploitDB (`searchsploit`) queries for detected services |
| **Template Scanning** | Nuclei community templates for HTTP/HTTPS vulnerability detection |
| **Smart-Check Filter** | 3-layer false positive reduction (Content-Type, size, magic bytes) |
| **Subnet Leak Detection** | Identifies hidden networks via HTTP redirect/header analysis |

### Reporting & Integration

| Capability | Description |
|:---|:---|
| **Multi-Format Output** | JSON, TXT, HTML dashboard, JSONL (ECS v8.11 compliant) |
| **Remediation Playbooks** | Markdown guides auto-generated per host/category |
| **Diff Analysis** | Compare JSON reports to track network changes over time |
| **SIEM-Ready Exports** | JSONL with risk scoring and observable hashing for deduplication |
| **Report Encryption** | AES-128-CBC (Fernet) with PBKDF2-HMAC-SHA256 key derivation |

### Operations

| Capability | Description |
|:---|:---|
| **Persistent Defaults** | User preferences stored in `~/.redaudit/config.json` |
| **IPv6 + Proxy Support** | Full dual-stack scanning with SOCKS5 pivoting |
| **Rate Limiting** | Configurable inter-host delay with ±30% jitter for IDS evasion |
| **Bilingual Interface** | Complete English/Spanish localization |
| **Auto-Update** | Atomic staged updates with automatic rollback on failure |

---

## How It Works

### Architecture Overview

RedAudit operates as an orchestration layer, managing concurrent execution threads for network interaction and data processing. It implements a two-phase architecture: generic discovery followed by targeted deep scans.

![System Overview](docs/images/system_overview_v3.png)

### Adaptive Scanning Logic

RedAudit does not apply a fixed scan profile to all hosts. Instead, it uses runtime heuristics to decide escalation:

```text
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: TCP Aggressive                  │
│              All hosts: -A -p- -sV -Pn                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Identity Evaluation  │
              │  • MAC extracted?     │
              │  • OS fingerprint?    │
              │  • Service versions?  │
              └───────────┬───────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
    ┌───────────────┐          ┌────────────────┐
    │ SUFFICIENT    │          │ AMBIGUOUS HOST │
    │ Stop scanning │          │ Continue...    │
    └───────────────┘          └───────┬────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────┐
                    │     PHASE 2a: Priority UDP           │
                    │  17 common ports (DNS, DHCP, SNMP)   │
                    └──────────────────┬───────────────────┘
                                       │
                          ┌────────────┴────────────┐
                          │                         │
                          ▼                         ▼
                  ┌───────────────┐        ┌────────────────┐
                  │ Identity found│        │ Still ambiguous│
                  │ Stop          │        │ (full mode)    │
                  └───────────────┘        └───────┬────────┘
                                                   │
                                                   ▼
                              ┌─────────────────────────────────┐
                              │     PHASE 2b: Extended UDP      │
                              │  --top-ports N (configurable)   │
                              └─────────────────────────────────┘
```

**Trigger Heuristics** (what makes a host "ambiguous"):

- Few open ports (≤3)
- Suspicious services (`unknown`, `tcpwrapped`)
- Missing MAC/vendor data
- Filtered or no-response ports

**Result**: 50-80% faster scans compared to always-on UDP, while maintaining detection quality for IoT devices, filtered services, and legacy equipment.

### Concurrency Model

RedAudit uses Python's `ThreadPoolExecutor` to scan multiple hosts simultaneously.

| Parameter | Default | Range | Notes |
|:---|:---|:---|:---|
| `--threads` | 6 | 1-16 | Threads share memory, execute nmap independently |
| `--rate-limit` | 0 | 0-∞ | Seconds between hosts (±30% jitter applied) |

**Guidance**:

- **High threads (10-16)**: Faster, but more network noise. Risk of congestion.
- **Low threads (1-4)**: Slower, stealthier, kinder to legacy networks.
- **Rate limit >0**: Recommended for production environments to avoid IDS triggers.

---

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

After installation, reload your shell configuration:

| Distribution | Default Shell | Command |
|:---|:---|:---|
| **Kali Linux** (2020.3+) | Zsh | `source ~/.zshrc` |
| **Debian / Ubuntu / Parrot** | Bash | `source ~/.bashrc` |

**Or simply open a new terminal window.**

### Post-Install Verification

```bash
which redaudit            # Should return: /usr/local/bin/redaudit
redaudit --version        # Should show current version
bash redaudit_verify.sh   # Full integrity check
```

---

## Usage

### Interactive Mode (Wizard)

Launch without arguments for guided setup:

```bash
sudo redaudit
```

The wizard will guide you through:

1. **Target Selection**: Choose a local subnet or enter manual CIDR
2. **Scan Mode**: Select FAST, NORMAL, or FULL
3. **Options**: Configure threads, rate limiting, encryption
4. **Authorization**: Confirm you have permission to scan

### Non-Interactive / Automation

```bash
# Quick host discovery
sudo redaudit --target 192.168.1.0/24 --mode fast --yes

# Standard security audit
sudo redaudit --target 192.168.1.0/24 --mode normal --yes

# Comprehensive audit with encryption
sudo redaudit --target 192.168.1.0/24 --mode full --encrypt --yes

# Stealthy scan with rate limiting
sudo redaudit --target 10.0.0.0/24 --mode normal --rate-limit 2 --threads 4 --yes

# Network discovery with topology mapping
sudo redaudit --target 192.168.1.0/24 --net-discovery --topology --yes

# Differential analysis (compare scans)
redaudit --diff ~/reports/monday.json ~/reports/friday.json
```

### Key CLI Options

| Option | Description |
|:---|:---|
| `-t, --target` | Target network(s) in CIDR notation |
| `-m, --mode` | Scan mode: `fast` / `normal` / `full` (default: normal) |
| `-j, --threads` | Concurrent threads (1-16, default: 6) |
| `--rate-limit` | Delay between hosts in seconds (±30% jitter) |
| `-e, --encrypt` | Encrypt reports with AES-128 |
| `-o, --output` | Output directory |
| `--topology` | Enable network topology discovery |
| `--net-discovery` | Enhanced L2/broadcast discovery |
| `--cve-lookup` | CVE correlation via NVD API |
| `--diff OLD NEW` | Differential analysis between scans |
| `--html-report` | Generate interactive HTML dashboard |
| `--stealth` | Enable paranoid timing for IDS evasion |
| `-y, --yes` | Skip confirmations (automation mode) |

See `redaudit --help` or [USAGE.md](docs/USAGE.en.md) for the complete list of 40+ options.

---

## Configuration

### Scan Behavior

| Parameter | Purpose | Recommendation |
|:---|:---|:---|
| `--threads N` | Parallel host scanning | 6 for balanced, 2-4 for stealth |
| `--rate-limit N` | Inter-host delay (seconds) | 1-5s for production environments |
| `--udp-ports N` | UDP ports in full mode | 100 (default), up to 500 for thorough |
| `--stealth` | Paranoid mode | Use when IDS evasion is critical |

### Output & Encryption

Reports are saved to `~/Documents/RedAuditReports` (default) with timestamps.

**Encryption** (when `-e, --encrypt` is used):

1. A random 16-byte salt is generated
2. Your password derives a 32-byte key via PBKDF2-HMAC-SHA256 (480k iterations)
3. Files are encrypted using Fernet (AES-128-CBC)
4. A `.salt` file is saved alongside encrypted reports

**Decryption**:

```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

### Persistence

Store defaults to avoid repeating flags:

```bash
redaudit --target 192.168.1.0/24 --threads 8 --rate-limit 1 --save-defaults --yes
# Future runs will use these settings automatically
```

Defaults are stored in `~/.redaudit/config.json`.

---

## Toolchain Reference

RedAudit orchestrates these tools:

| Category | Tools | Purpose |
|:---|:---|:---|
| **Core Scanner** | `nmap`, `python3-nmap` | TCP/UDP scanning, service/version detection, OS fingerprinting |
| **Web Recon** | `whatweb`, `curl`, `wget`, `nikto` | HTTP headers, technologies, vulnerabilities |
| **Template Scanner** | `nuclei` | Community-driven vulnerability templates |
| **Exploit Intel** | `searchsploit` | ExploitDB lookup for detected services |
| **CVE Intelligence** | NVD API | CVE correlation for service versions |
| **SSL/TLS Analysis** | `testssl.sh` | Deep SSL/TLS vulnerability scanning |
| **Traffic Capture** | `tcpdump`, `tshark` | Packet capture for protocol analysis |
| **DNS/Whois** | `dig`, `whois` | Reverse DNS and ownership lookup |
| **Topology** | `arp-scan`, `ip route` | L2 discovery, VLAN detection, gateway mapping |
| **Net Discovery** | `nbtscan`, `netdiscover`, `fping`, `avahi` | Broadcast/L2 discovery |
| **Red Team Recon** | `snmpwalk`, `enum4linux`, `masscan`, `kerbrute` | Optional active enumeration (opt-in) |
| **Encryption** | `python3-cryptography` | AES-128 encryption for reports |

### Project Structure

```text
redaudit/
├── core/                   # Core functionality
│   ├── auditor.py          # Main orchestrator
│   ├── wizard.py           # Interactive UI (WizardMixin)
│   ├── scanner.py          # Nmap scanning logic + IPv6
│   ├── nuclei.py           # Nuclei template scanner integration
│   ├── prescan.py          # Asyncio fast port discovery
│   ├── hyperscan.py        # Ultra-fast parallel discovery
│   ├── topology.py         # Network topology discovery
│   ├── net_discovery.py    # Enhanced L2/broadcast discovery
│   ├── reporter.py         # JSON/TXT/HTML/JSONL output
│   ├── playbook_generator.py # Remediation playbook generator
│   ├── nvd.py              # CVE correlation via NVD API
│   ├── siem.py             # SIEM integration (ECS v8.11)
│   ├── diff.py             # Differential analysis
│   ├── crypto.py           # AES-128 encryption/decryption
│   ├── command_runner.py   # Safe external command execution
│   ├── verify_vuln.py      # Smart-Check false positive filter
│   └── updater.py          # Auto-update system
├── templates/              # HTML report templates
└── utils/                  # Utilities (i18n, config, constants)
```

---

## Reference

### Terminology

| Term | Definition |
|:---|:---|
| **Deep Scan** | Selective escalation (TCP + UDP fingerprinting) for ambiguous hosts |
| **HyperScan** | Ultra-fast async discovery module (batch TCP, UDP IoT, aggressive ARP) |
| **Smart-Check** | 3-layer false positive filter (Content-Type, size, magic bytes) |
| **Entity Resolution** | Consolidation of multi-interface devices into unified assets |
| **ECS** | Elastic Common Schema v8.11 for SIEM compatibility |
| **Finding ID** | Deterministic SHA256 hash for cross-scan correlation |
| **CPE** | Common Platform Enumeration v2.3 for NVD matching |
| **JSONL** | JSON Lines format for streaming SIEM ingestion |
| **Fernet** | Symmetric encryption (AES-128-CBC + HMAC-SHA256) |
| **PBKDF2** | Password-based key derivation (480k iterations) |
| **Thread Pool** | Concurrent workers for parallel host scanning |
| **Rate Limiting** | Inter-host delay with ±30% jitter for IDS evasion |
| **Heartbeat** | Background thread that warns if scan is silent >300s |

### Troubleshooting

For comprehensive troubleshooting, see: 📖 **[Complete Troubleshooting Guide](docs/TROUBLESHOOTING.en.md)**

**Quick Links**:

- [Installation Issues](docs/TROUBLESHOOTING.en.md#1-permission-denied--root-privileges-required)
- [Scanning Problems](docs/TROUBLESHOOTING.en.md#5-scan-appears-frozen--long-pauses)
- [Network Discovery Issues](docs/TROUBLESHOOTING.en.md#12-net-discovery-missing-tools--tool_missing-v32)
- [Encryption/Decryption](docs/TROUBLESHOOTING.en.md#8-decryption-failed-invalid-token)

### Logging

Debug logs are stored in `~/.redaudit/logs/` (rotation: 5 files, 10MB each).

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details.

## License

RedAudit is released under the **GNU General Public License v3.0 (GPLv3)**. See [LICENSE](LICENSE).

---

## Legal Notice

**RedAudit** is a security tool for **authorized auditing only**. Scanning networks without permission is illegal. By using this tool, you accept full responsibility for your actions and agree to use it only on systems you own or have explicit authorization to test.

---

[Full Documentation](docs/INDEX.md) | [Report Schema](docs/REPORT_SCHEMA.en.md) | [Security Specs](docs/SECURITY.en.md)
