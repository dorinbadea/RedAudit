# RedAudit

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](README_ES.md)

![Version](https://img.shields.io/badge/v3.8.7-blue?style=flat-square)
![Python](https://img.shields.io/badge/python_3.9+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/GPLv3-green?style=flat-square)
[![Tests](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/dorinbadea/81671a8fffccee81ca270f14d094e5a1/raw/redaudit-tests.json&style=flat-square)](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml)
![Coverage](https://img.shields.io/badge/coverage-84%25-brightgreen?style=flat-square)

<div align="center">

<img src="assets/Banner_en.png" alt="RedAudit banner">

</div>

## What is RedAudit?

RedAudit is a network auditing framework that orchestrates industry-standard security tools (nmap, nikto, testssl, nuclei) plus optional helpers into an adaptive, multi-phase pipeline. It automates discovery-to-report workflows with topology signals and optional agentless probes, producing structured JSON/HTML/JSONL artifacts suitable for SIEM ingestion or compliance reporting.

**Use cases**: Defensive hardening, penetration test scoping, change tracking between assessments.

**Key differentiator**: Identity-driven escalation across scan phases (TCP → Priority UDP → Extended UDP), not just parallel tool execution.

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
| **Adaptive Deep Scan** | 3-phase escalation (TCP → Priority UDP → Extended UDP) only when identity is weak or host is unresponsive |
| **HyperScan** | Async batch TCP + UDP IoT broadcast + aggressive ARP for ultra-fast triage |
| **Topology Discovery** | L2/L3 mapping (ARP/VLAN/LLDP + gateway/routes) for hidden network detection |
| **Network Discovery** | Broadcast protocols (DHCP/NetBIOS/mDNS/UPNP) for guest network detection |
| **Agentless Verification** | Optional SMB/RDP/LDAP/SSH/HTTP probes with device fingerprinting (vendor/service patterns) |
| **Stealth Mode** | T1 paranoid timing, single-thread, 5s+ delays for enterprise IDS evasion |

### Intelligence & Correlation

| Capability | Description |
|:---|:---|
| **CVE Correlation** | NVD API 2.0 with CPE 2.3 matching and 7-day cache |
| **Exploit Lookup** | Automatic ExploitDB (`searchsploit`) queries for detected services |
| **Template Scanning** | Nuclei community templates with false positive detection (server header vs vendor mapping) |
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
| **Interactive Webhooks** | Real-time alerts via Slack, Teams, or PagerDuty (wizard-configurable) |
| **Session Logging** | Dual-format terminal output capture (`.log` raw + `.txt` clean) for audit trails |
| **Timeout-Safe Scanning** | Host scans are bounded by hard timeouts; progress shows upper-bound ETA |
| **IPv6 + Proxy Support** | Full dual-stack scanning with SOCKS5 pivoting |
| **Rate Limiting** | Configurable inter-host delay with ±30% jitter for IDS evasion |
| **Bilingual Interface** | Complete English/Spanish localization |
| **Auto-Update** | Atomic staged updates with automatic rollback on failure |

---

## How It Works

### Architecture Overview

RedAudit operates as an orchestration layer, managing concurrent execution threads for network interaction and data processing. It implements a two-phase architecture: generic discovery followed by targeted deep scans.

![System Overview](docs/images/system_overview_en.png)

### Adaptive Scanning Logic

RedAudit does not apply a fixed scan profile to all hosts. Instead, it uses runtime heuristics to decide escalation, including short HTTP title/meta/heading probes on common login paths for quiet hosts:

```text
┌─────────────────────────────────────────────────────────────┐
│              PHASE 1: Mode-Specific Nmap Profile            │
│        fast/normal/full modes drive the base scan           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Identity Evaluation  │
              │  • MAC/vendor?        │
              │  • Hostname/DNS?      │
              │  • Service version?   │
              │  • CPE/banner?        │
              │  • HTTP title/heading?│
              │  • Agentless hints?   │
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
                    │   PHASE 2a: Priority UDP             │
                    │   17 common ports (DNS, DHCP, SNMP)  │
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
                              │   PHASE 2b: Extended UDP        │
                              │  --top-ports N (configurable)   │
                              └─────────────────────────────────┘
```

In **full/completo** mode, the base profile is already aggressive, so deep identity scan triggers less often and only when identity remains weak or signals are suspicious.

**Trigger Heuristics** (what makes a host "ambiguous", mostly in fast/normal):

- Few open ports (≤3)
- Suspicious services (`unknown`, `tcpwrapped`)
- Missing MAC/vendor/hostname
- No version info (low identity score)
- Filtered or no-response ports (deep scan fallback)
- Quiet hosts with vendor hints may get a short HTTP/HTTPS title/meta/heading probe on common ports

**Result**: Faster scans than always-on UDP, while preserving identity for IoT, filtered services, and legacy devices.

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

### Docker (Windows / macOS / Linux)

Works on any platform with Docker Desktop. See **[Docker Guide](docs/DOCKER.md)** for detailed setup.

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest

# Interactive wizard
docker run -it --rm -v $(pwd)/reports:/reports ghcr.io/dorinbadea/redaudit:latest

# Direct scan
docker run --rm -v $(pwd)/reports:/reports \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
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

The wizard offers 4 audit profiles:

- **Express**: Fast discovery (host-only, no port scanning)
- **Standard**: Balanced audit (top 1000 ports + vulnerability checks)
- **Exhaustive**: Maximum coverage (all 65535 ports + UDP 500 + Red Team + CVE correlation)
- **Custom**: Full 8-step wizard for granular control

After selecting a profile, you'll configure:

1. **Target Selection**: Choose a local subnet or enter manual CIDR
2. **Timing Mode**: Select Stealth (T1), Normal (T4), or Aggressive (T5)
3. **Options**: Configure threads, rate limiting, encryption (varies by profile)
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

### Timing Modes

RedAudit applies nmap timing templates based on your selection:

| Mode | Nmap Template | Threads | Delay | Use Case |
|:---|:---|:---|:---|:---|
| **Stealth** | `-T1` | 4 | 300ms | IDS evasion, noisy networks, legacy devices |
| **Normal** | `-T4` | 16 | 0ms | Standard audits (default, balanced speed/noise) |
| **Aggressive** | `-T5` | 32 | 0ms | Time-critical scans, trusted networks |

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
| **Template Scanner** | `nuclei` | Optional template scanner (enable via wizard or `--nuclei`) |
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
│   ├── network.py          # Network interface detection
│   ├── hyperscan.py        # Ultra-fast parallel discovery
│   ├── net_discovery.py    # Enhanced L2/broadcast discovery
│   ├── topology.py         # Network topology discovery
│   ├── udp_probe.py        # UDP probing helpers
│   ├── agentless_verify.py # Agentless SMB/RDP/LDAP/SSH/HTTP checks
│   ├── nuclei.py           # Nuclei template scanner integration
│   ├── playbook_generator.py # Remediation playbook generator
│   ├── nvd.py              # CVE correlation via NVD API
│   ├── osquery.py          # Osquery verification helpers (optional)
│   ├── entity_resolver.py  # Asset consolidation / entity resolution
│   ├── evidence_parser.py  # Evidence parsing helpers
│   ├── reporter.py         # JSON/TXT/HTML/JSONL output
│   ├── html_reporter.py    # HTML report renderer
│   ├── jsonl_exporter.py   # JSONL export for SIEM
│   ├── siem.py             # SIEM integration (ECS v8.11)
│   ├── diff.py             # Differential analysis
│   ├── crypto.py           # AES-128 encryption/decryption
│   ├── command_runner.py   # Safe external command execution
│   ├── power.py            # Sleep inhibition helpers
│   ├── proxy.py            # Proxy handling
│   ├── scanner_versions.py # External tool version detection
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
| **Deep Scan** | Selective escalation (TCP + UDP fingerprinting) when identity is weak or host is unresponsive |
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
