# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](IMPROVEMENTS_ES.md)

This document outlines the technical roadmap, planned architectural improvements, and discarded approaches for RedAudit.

## Immediate Roadmap (v3.1+)

| Priority | Feature | Description |
| :--- | :--- | :--- |
| **High** | **Configurable UDP Ports** | Add `--udp-ports N` CLI flag (range: 50-500, default: 100) for user-tunable UDP scan coverage. |
| **Medium** | **NetBIOS/mDNS Discovery** | Active hostname queries (port 137/5353) for improved entity resolution on networks without DNS PTR records. |
| **Medium** | **Containerization** | Official Dockerfile and Docker Compose setup for ephemeral audit containers. |
| **Low** | **Expand Persistent Configuration** | Extend `~/.redaudit/config.json` beyond NVD key (e.g., default threads, output dir, rate limits) and optionally support YAML import/export. |

## Architectural Proposals

### 1. Modular Plugin Engine

**Status**: Under Consideration
**Concept**: Decouple the core scanner from tools. Allow Python-based "Plugins" to define new tool wrappers (e.g., specific IoT scanners) without modifying core logic.
**Benefit**: easier community contribution and extensibility.

### 2. Distributed Scanning (Coordinator/Workers)

**Status**: Long-term
**Concept**: Separate the Orchestrator from verify workers.

- Central API (Coordinator) distributes targets.
- Remote Workers (Nodes) execute scans and return JSON.

### 3. Persistent Configuration

**Status**: Planned
**Concept**: Expand user configuration in `~/.redaudit/config.json` to override defaults (removing need for repetitive CLI flags). Optionally add YAML import/export for convenience.

## Completed Milestones

### v3.0.1 (Completed - December 2025) -> **CURRENT**

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
- [x] **Concurrent PCAP**: Traffic captured during scans, not after
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
3. Read [CONTRIBUTING.md](https://github.com/dorinbadea/RedAudit/blob/main/CONTRIBUTING.md).
4. Open a [Discussion](https://github.com/dorinbadea/RedAudit/discussions) for new ideas.

---

**Active Maintenance** | *Last Update: December 2025*

*If this document is not updated in >6 months, the project may be paused. In that case, consider forking or contacting me.*
