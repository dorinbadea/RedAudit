# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](IMPROVEMENTS_ES.md)

This document outlines the technical roadmap, planned architectural improvements, and discarded approaches for RedAudit.

## Immediate Roadmap (v2.7+)

| Priority | Feature | Description |
| :--- | :--- | :--- |
| **High** | **IPv6 Support** | Implement full `nmap -6` support and IPv6 regex validation in the InputSanitizer module. |
| **High** | **CVE Correlation** | Deepen vulnerability analysis by correlating identified versions with NVD (beyond SearchSploit). |
| **Medium** | **Differential Analysis** | Create a `diff` module to compare two JSON reports and highlight delta (new ports/vulns). |
| **Medium** | **Proxy Chains** | Native support for SOCKS5 proxies to facilitate pivoting. |
| **Low** | **Containerization** | Official Dockerfile and Docker Compose setup for ephemeral audit containers. |

## Architectural Proposals

### 1. Modular Plugin Engine

**Status**: Under Consideration
**Concept**: Decouple the core scanner from tools. Allow Python-based "Plugins" to define new tool wrappers (e.g., specific IoT scanners) without modifying core logic.
**Benefit**: easier community contribution and extensibility.

### 2. Distributed Scanning (Master/Slave)

**Status**: Long-term
**Concept**: Separate the Orchestrator from verify workers.

- Central API (Master) distributes targets.
- Remote Agents (Slaves) execute scans and return JSON.

### 3. Persistent Configuration

**Status**: Planned
**Concept**: Allow user configuration in `~/.redaudit/config.yaml` to override defaults (removing need for repetitive CLI flags).

## Completed Milestones

### v2.9.0 (Completed - December 2025) -> **CURRENT**

*Focus on intelligence, efficiency, and professional documentation.*

- [x] **Smart-Check**: 90% reduction in false positives for web scanning.
- [x] **UDP Taming**: 50-80% faster scans via optimized 3-phase strategy.
- [x] **Entity Resolution**: Grouping of multi-interface devices (Unified Assets).
- [x] **SIEM Professional**: ECS v8.11 compliance and risk scoring.
- [x] **Clean Documentation**: Complete removal of legacy version tags and standardization.

### v2.6-v2.8 (Completed)

*Focus on security, professionalism, and external tool integration.*

- [x] **Exploit Intelligence**: Integrated `searchsploit` for automatic exploit lookup based on service version.
- [x] **SSL/TLS Auditing**: Integrated `testssl.sh` for deep cryptographic analysis of HTTPS services.
- [x] **Security Hardening**: Increased password complexity requirements (12+ chars, mixed case, numbers).
- [x] **CI/CD Security**: Added Dependabot (weekly updates) and CodeQL (static analysis) to GitHub Actions.
- [x] **UX Improvements**: Added `rich` progress bars with graceful fallback.
- [x] **Documentation**: Added architecture diagrams (Mermaid), activation matrices, and professionalized all manuals.

### v2.6 (Completed - December 2025)

*Focus on code quality, testing, and modularization.*

- [x] **Modular Architecture**: Refactored into Python package structure
- [x] **CI/CD Pipeline**: GitHub Actions for automated testing (Python 3.9-3.12)
- [x] **Test Suite**: Expanded to 34 automated tests (89% coverage)
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

<div align="center">

**Active Maintenance**
*Last Update: December 2025*

<sub>If this document is not updated in >6 months, the project may be paused. In that case, consider forking or contacting me.</sub>

</div>
