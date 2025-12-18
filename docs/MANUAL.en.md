# RedAudit User Manual

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](MANUAL.es.md)

**Audience:** Security Analysts, Architects
**Scope:** Architecture, capabilities, workflow logic, toolchain reference.
**Source of Truth:** `redaudit/core/orchestrator.py`

---

## 1. Introduction

RedAudit is an automated network auditing framework designed for **defensive hardening** and **authorized offensive assessments**. Unlike simple port scanners, it orchestrates a concurrent pipeline of industry-standard tools (`nmap`, `nikto`, `nuclei`, `testssl.sh`) to provide actionable intelligence.

It is designed to be **secure by default**, **deterministic**, and **operator-driven**—automating the repetitive discovery phase so analysts can focus on exploitation or remediation.

---

## 2. Core Capabilities

RedAudit aggregates capabilities into four operational domains:

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

## 3. Installation & Setup

### Requirements

- **OS**: Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS
- **Privileges**: `sudo` / root recommended (for raw sockets, OS detection, PCAP)
- **Python**: 3.9+

### Quick Install

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
source ~/.zshrc  # or ~/.bashrc
```

The installer handles all dependencies, sets up the python environment, and creates the `redaudit` alias.

---

## 4. Architecture & Workflow

### Logic Flow

RedAudit operates as an orchestration layer. It does not blindly run every tool on every host. Instead, it uses an **Adaptive Logic** engine:

```
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

**Trigger Heuristics** (Automatic Escalation):
RedAudit escalates to deep scanning if:

1. Less than 3 open ports are found.
2. Services are identified as `unknown` or `tcpwrapped`.
3. MAC/Vendor data is missing.
4. Host seems alive but unresponsive to standard probes.

### Scan Modes

| Mode | CLI Flag | Behavior | Use Case |
|:---|:---|:---|:---|
| **Fast** | `--mode fast` | Host Discovery (`-sn`) only. | Quick inventory, reachability check. |
| **Normal** | `--mode normal` | Top Ports, Versions, Service Scripts. | Standard security audit. |
| **Full** | `--mode full` | All Ports, Web Recon, SSL, Nuclei, UDP. | Comprehensive pre-pentest analysis. |

---

## 5. Usage Guide

### Interactive Mode (Wizard)

Simply run `sudo redaudit` to enter the text-based UI.

1. **Target**: IP/CIDR selection.
2. **Mode**: Scan profile selection.
3. **Options**: Encryption, threads, etc.
4. **Execution**: Running the scan.

### Non-Interactive (Automation)

For scripts and CI/CD, use the CLI flags with `--yes`.

#### Examples

```bash
# Quick LAN inventory
sudo redaudit --target 192.168.1.0/24 --mode fast --yes

# Standard Audit with Encryption
sudo redaudit --target 10.0.0.0/24 --mode normal --encrypt --yes

# Stealth Scan (Low noise)
sudo redaudit --target 192.168.1.50 --threads 2 --rate-limit 5 --yes

# Differential Analysis (Compare two reports)
redaudit --diff report_monday.json report_friday.json
```

### Key CLI Flags

| Flag | Purpose |
|:---|:---|
| `-t, --target` | CIDR range(s) to scan. |
| `-m, --mode` | `fast`, `normal`, `full`. |
| `-j, --threads` | Parallel host workers (1-16, Default: 6). |
| `--rate-limit` | Seconds delay between hosts (±30% jitter). |
| `--encrypt` | Encrypt outputs with AES-128. |
| `--net-discovery` | Enable active L2/Broadcast discovery. |
| `--topology` | Enable L2/L3 topology mapping. |
| `--html-report` | Generate interactive dashboard. |
| `--webhook URL` | Send real-time findings to Slack/Teams. |
| `--save-defaults` | Persist current settings to config. |

---

## 6. Reports & Tools

### Directory Structure

Reports are saved in `~/Documents/RedAuditReports/` by default.

```text
RedAudit_2025-01-15_21-30-45/
├── redaudit_20250115.json      # Complete machine-readable data
├── redaudit_20250115.txt       # Executive summary text
├── report.html                 # Interactive HTML Dashboard
├── findings.jsonl              # SIEM ingest events (v8.11 ECS)
├── assets.jsonl                # SIEM asset inventory
└── playbooks/                  # Markdown remediation guides
```

### Toolchain Reference

RedAudit orchestrates these underlying tools:

| Category | Tools | Report Section |
|:---|:---|:---|
| **Core Scanner** | `nmap`, `python3-nmap` | `hosts[].ports` |
| **Web Recon** | `whatweb`, `curl`, `wget`, `nikto` | `vulnerabilities` |
| **Template Scanner**| `nuclei` | `vulnerabilities` |
| **SSL/TLS** | `testssl.sh`, `openssl` | `vulnerabilities.tls` |
| **Exploits** | `searchsploit` | `ports[].known_exploits` |
| **CVEs** | NVD API | `ports[].cve` |
| **Network** | `arp-scan`, `tshark`, `tcpdump` | `network_discovery` |

### SIEM Integration

When encryption is disabled, `findings.jsonl` provides a flat event stream compatible with Elastic Common Schema (ECS) v8.11, ideal for ingestion into ELK, Splunk, or Graylog.

---

## 7. Security & Troubleshooting

### Security Model

- **Privileges**: Uses `sudo` only for necessary operations (nmap sockets).
- **Encryption**: Uses AES-128-CBC (Fernet) + PBKDF2-HMAC-SHA256 (32-byte key).
- **Input Validation**: Strict type checking on all CLI arguments; no `shell=True`.

### Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.en.md) for detailed error codes.

**Common Issues:**

- **Permission Denied**: Run with `sudo`.
- **Missing Tools**: Re-run `bash redaudit_install.sh`.
- **Decryption Failed**: Ensure `.salt` file exists next to `.enc` file.

---

[Back to README](../README.md)
