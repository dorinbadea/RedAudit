# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ROADMAP_ES.md)

This document outlines the technical roadmap, planned architectural improvements, and discarded approaches for RedAudit.

## Immediate Roadmap (v3.1+)

| Priority | Feature | Status | Description |
| :--- | :--- | :--- | :--- |
| **High** | **Network Topology Discovery** | ✅ Implemented (best-effort) | Optional topology discovery (ARP/VLAN/LLDP + gateway/routes) focused on "hidden network" hints and L2 context. |
| **High** | **Configurable UDP Ports** | ✅ Implemented | Added `--udp-ports N` CLI flag (range: 50-500, default: 100) for user-tunable UDP scan coverage in full UDP identity mode. |
| **Medium** | **NetBIOS/mDNS Discovery** | Planned | Active hostname queries (port 137/5353) for improved entity resolution on networks without DNS PTR records. |
| **Medium** | **Containerization** | Paused | Official Dockerfile and Docker Compose setup for ephemeral audit containers. |
| **Low** | **Expand Persistent Configuration** | ✅ Implemented (initial) | Extended `~/.redaudit/config.json` beyond NVD key (persist common defaults like threads/output/rate-limit/UDP/topology/lang). |

### Network Topology Discovery (v4.0 Target)

**Goal**: Fast pre-scan reconnaissance to map network architecture before deep scanning.

**Current status (v3.1+)**: A baseline best-effort implementation is available (routes/default gateway, ARP scan, VLAN hints, LLDP/CDP best-effort). v4.0 expands this with richer active discovery (nmap broadcast scripts, traceroute path mapping, etc.).

| Capability | Tool | Output |
| :--- | :--- | :--- |
| **L2 Host Discovery** | `arp-scan --localnet` | MAC addresses + vendor OUI |
| **VLAN Detection** | `nmap --script broadcast-dhcp-discover,broadcast-arp` | VLAN IDs, DHCP servers |
| **Gateway Mapping** | `traceroute` + ICMP redirect analysis | Router paths, NAT detection |
| **L2 Topology** | CDP/LLDP parsing via `tcpdump -nn -v -c 50 ether proto 0x88cc` | Switch/port relationships |
| **Hidden Networks** | ARP anomaly detection + route table analysis | Bridged/misconfigured subnets |

**CLI Options**:

```bash
redaudit --topology-only --target 192.168.0.0/16 --yes  # Quick topology scan (no host scan)
redaudit --topology --target 10.0.0.0/8 --yes           # Integrated with full audit
```

## Architectural Proposals

### 1. Modular Plugin Engine

**Status**: Under Consideration
**Concept**: Decouple the core scanner from tools. Allow Python-based "Plugins" to define new tool wrappers (e.g., specific IoT scanners) without modifying core logic.
**Benefit**: easier community contribution and extensibility.

**Note**: A "plugin-first" architecture is currently deferred; priority is stability and coherent core behavior.

### 2. Distributed Scanning (Coordinator/Workers)

**Status**: Long-term
**Concept**: Separate the Orchestrator from verify workers.

- Central API (Coordinator) distributes targets.
- Remote Workers (Nodes) execute scans and return JSON.

### 3. Persistent Configuration

**Status**: Planned
**Concept**: Expand user configuration in `~/.redaudit/config.json` to override defaults (removing need for repetitive CLI flags). Optionally add YAML import/export for convenience.

## Completed Milestones

### v3.1.3 (Completed - December 2025) -> **CURRENT**

*Patch release focused on asyncio performance improvements.*

- [x] **Async UDP probe**: Fast concurrent probing of priority UDP ports during deep scan.
- [x] **Async topology discovery**: Parallelized command collection (ARP/VLAN/LLDP + gateway).

### v3.1.2 (Completed - December 2025)

*Patch release focused on auto-update UX improvements.*

- [x] **CLI-friendly update notes**: Terminal-friendly rendering (strip Markdown noise).
- [x] **Reliable restart**: PATH-aware restart with clear fallback instructions.
- [x] **Clearer prompts**: UDP presets, topology-only clarification, save-defaults confirmation.

### v3.1.1 (Completed - December 2025)

*Patch release focused on topology discovery, persistent defaults, and configurable UDP coverage.*

- [x] **Topology discovery (best-effort)**: ARP/VLAN/LLDP + gateway/routes mapping (`--topology`, `--topology-only`).
- [x] **Persistent defaults**: Save common settings to `~/.redaudit/config.json` (`--save-defaults`).
- [x] **Configurable UDP coverage**: `--udp-ports N` to tune full UDP identity scan coverage.
- [x] **Docs & tests alignment**: Updated manuals, schema docs, and unit tests.

### v3.1.0 (Completed - December 2025)

*Feature release focused on SIEM readiness and AI pipeline exports.*

- [x] **JSONL exports**: `findings.jsonl`, `assets.jsonl`, `summary.json` for flat ingestion.
- [x] **Deterministic finding IDs**: `finding_id` for cross-scan correlation and dedup.
- [x] **Finding categorization**: surface/misconfig/crypto/auth/info-leak/vuln.
- [x] **Normalized severity**: `normalized_severity` (0-10) + preserved original tool severity.
- [x] **Parsed observations**: Structured extraction from Nikto/TestSSL (with raw evidence externalization when needed).
- [x] **Scanner versions**: Tool provenance (`scanner_versions`).

### v3.0.4 (Completed - December 2025)

*Patch release focused on clearer interactive host-limit UX and documentation alignment.*

- [x] **Host limit default = all**: Interactive prompt defaults to scanning all discovered hosts (ENTER = all / todos).
- [x] **Clearer wording**: Numbers now clearly mean a maximum host count (cap), not a host selector.

### v3.0.3 (Completed - December 2025)

*Patch release focused on auto-update transparency and language preservation.*

- [x] **Language preserved on update**: Auto-update keeps the previously installed language (e.g., Spanish stays Spanish).
- [x] **Verbose update output**: Shows target ref/commit, system file changes (+/~/-), and explicit install/backup steps.

### v3.0.2 (Completed - December 2025)

*Patch release focused on CLI polish, reporting clarity, and safer CVE enrichment.*

- [x] **Thread-safe CLI output**: Prevents interleaved log lines and mid-word wrapping.
- [x] **Spanish UX improvements**: Completed missing translations for scan status/progress messages.
- [x] **PCAP visibility**: Final summary shows PCAP count; TXT report includes PCAP path when captured.
- [x] **NVD enrichment safety**: Avoid wildcard CPE queries when version is unknown; correct API key source messaging.

### v3.0.1 (Completed - December 2025)

*Patch release focused on configuration, update hardening, and documentation alignment.*

- [x] **Persistent NVD API Key Storage**: Store/read NVD API key via config file + environment variable.
- [x] **Updater Verification**: Auto-update resolves the published Git tag and verifies commit hash before installing.
- [x] **Pinned testssl.sh Install**: Installer pins `testssl.sh` to a known tag/commit and verifies it before linking.
- [x] **NVD Resilience**: Retry with backoff on transient NVD API errors (429/5xx/network).
- [x] **Limited Non-Root Mode**: `--allow-non-root` allows running without sudo (limited capabilities).

### v3.0.0 (Completed - December 2025)

*Major feature release with advanced capabilities.*

- [x] **IPv6 Support**: Full scanning capabilities for IPv6 networks.
- [x] **Magic Byte Validation**: Enhanced false positive detection with file signature verification.
- [x] **CVE Correlation (NVD)**: Deep vulnerability intelligence via NIST NVD API with 7-day cache.
- [x] **Differential Analysis**: Compare two JSON reports to detect network changes.
- [x] **Proxy Chains (SOCKS5)**: Network pivoting support via proxychains wrapper.
- [x] **Enhanced Auto-Update**: Git clone approach with verification and home folder copy.

### v2.9.0 (Completed - December 2025)

*Focus on intelligence, efficiency, and professional documentation.*

- [x] **Smart-Check**: 90% reduction in false positives for web scanning.
- [x] **UDP Taming**: 50-80% faster scans via optimized 3-phase strategy.
- [x] **Entity Resolution**: Grouping of multi-interface devices (Unified Assets).
- [x] **SIEM Professional**: ECS v8.11 compliance and risk scoring.
- [x] **Clean Documentation**: Complete removal of legacy version tags and standardization.

### v2.7-v2.8 (Completed)

*Focus on concurrency, security, and external tool integration.*

- [x] **Adaptive Deep Scan**: 3-phase strategy (TCP aggressive → Priority UDP → Full UDP)
- [x] **Concurrent PCAP**: Traffic captured during deep scans, not after
- [x] **Secure Auto-Update**: GitHub-integrated with automatic restart
- [x] **Pre-scan Engine**: Fast asyncio port discovery before nmap
- [x] **Exploit Intelligence**: SearchSploit integration for version-based lookups
- [x] **SSL/TLS Analysis**: TestSSL.sh deep vulnerability scanning
- [x] **Security Hardening**: Strong password requirements (12+ chars)
- [x] **CI/CD Security**: Dependabot + CodeQL static analysis
- [x] **UX Improvements**: Rich progress bars with graceful fallback

### v2.6 (Completed)

*Focus on code quality, testing, and modularization.*

- [x] **Modular Architecture**: Refactored into Python package structure
- [x] **CI/CD Pipeline**: GitHub Actions for automated testing (Python 3.9-3.12)
- [x] **Test Suite**: Expanded automated tests and introduced CI coverage reporting (tracked by CI, not hard-coded here)
- [x] **Named Constants**: All magic numbers replaced
- [x] **Backward Compatibility**: Original `redaudit.py` preserved as wrapper

## Discarded Concepts

| Proposal | Reason for Rejection |
| :--- | :--- |
| **Web GUI (Controller)** | Increases attack surface and dependency weight. RedAudit is designed as a headless CLI tool for automation and pipelining. |
| **Active Exploitation** | Out of scope. RedAudit is an *auditing* and *discovery* tool, not an exploitation framework (like Metasploit). |
| **Native Windows Support** | Too complex to maintain solo due to raw socket requirements. Use WSL2 or Docker. |
| **PDF Generation** | Adds heavy dependencies (LaTeX/ReportLab). JSON output should be consumed by external reporting tools instead. |

---

## Contributing

If you wish to contribute to any of these features:

1. Check existing [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Comment before starting to avoid duplication.
3. Read [CONTRIBUTING.md](../.github/CONTRIBUTING.md).
4. Open a [Discussion](https://github.com/dorinbadea/RedAudit/discussions) for new ideas.

---

**Active Maintenance** | *Last Update: December 2025*

*If this document is not updated in >6 months, the project may be paused. In that case, consider forking or contacting me.*
