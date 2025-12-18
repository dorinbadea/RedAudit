# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ROADMAP.es.md)

**Audience:** Contributors, Stakeholders
**Scope:** Planned features, authorized proposals, historical changelog.
**Source of Truth:** Repository Code state & Git History

---

This document outlines the technical roadmap, verifies implemented capabilities, and documents discarded approaches for RedAudit.

## 1. Active Roadmap (Upcoming Features)

These features are approved but **not yet implemented** in the codebase.

### Security & Integrations (Priority: High)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Native SIEM Pipeline** | 🎯 Planned | Bundled configuration for Filebeat/Logstash to ingest RedAudit ECS JSON directly. Creation of Sigma rules for common findings. |
| **Osquery Verification** | 🎯 Planned | Post-scan module to execute Osquery queries on live hosts (via fleet/SSH) to validate configs (firewall, running services). |
| **Interactive Webhooks** | 🎯 Planned | Add webhook URL configuration to the interactive wizard (currently CLI-only via `--webhook`). |

### Red Team Extensions (Priority: Medium)

*Requires specialized authorization and safe-guards.*

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Impacket Integration** | 🎯 Planned | Optional module `--redteam-deep` using `smbexec`/`secretsdump` (via Python library, not subprocess) on null sessions. |
| **BloodHound Collector** | 🎯 Planned | Execution of SharpHound/BloodHound.py on live Windows hosts to generate graph data for AD attack path analysis. |
| **Red Team Playbooks** | 🎯 Planned | Automated generation of PoC scripts (Python/Msfvenom suggestions) for verified exploitable findings (Labs only). |

### Infrastructure (Priority: Low)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **PyPI Distribution** | 🚧 Deferred | Publishing `pip install redaudit`. Blocked by need for extensive cross-platform testing. |
| **Containerization** | 🚧 Deferred | Official Docker image. Deferred in favor of standard pip/venv installation stability. |
| **Plugin Engine** | 🚧 Deferred | "Plugin-first" architecture to decouple core scanner from tools. |

---

## 2. Implemented Capabilities (Verified)

Features currently present using `redaudit --version` >= v3.6.0.

### Advanced Scanning & Automation

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Nuclei Integration** | v3.6.0 | Module `redaudit/core/nuclei.py`. Executes Nuclei templates if tool is found. |
| **Playbook Generation** | v3.4.0 | Module `redaudit/core/playbook_generator.py`. Creates MD remediation guides in `playbooks/`. |
| **Red Team: Kerberos** | v3.2.0 | Module `redaudit/core/net_discovery.py`. Uses `kerbrute` for user enumeration if approved. |
| **Red Team: SNMP/SMB** | v3.2.0 | Module `redaudit/core/net_discovery.py`. Uses `snmpwalk` and `enum4linux`. |
| **SIEM Readiness** | v3.1.0 | Module `redaudit/core/siem.py`. Outputs ECS v8.11 compliant JSON/JSONL. |
| **Differential Analysis** | v3.3.0 | Module `redaudit/core/diff.py`. Visual HTML diff of two scans. |

### Core & Stability

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Single Version Source** | v3.6.0 | `__init__.py` uses `importlib.metadata` from pyproject.toml. |
| **Centralized CommandRunner** | v3.5.0 | `redaudit/core/command_runner.py` handles all subprocesses safely. |
| **Persistent Config** | v3.1.1 | `~/.redaudit/config.json` stores user defaults. |
| **Async Discovery** | v3.1.3 | `redaudit/core/hyperscan.py` uses `asyncio` for fast port probing. |

---

## 3. Discarded Concepts

Ideas considered but rejected to maintain project focus.

| Proposal | Reason for Rejection |
| :--- | :--- |
| **Web GUI (Controller)** | Increases attack surface and dependency weight. RedAudit is designed as a headless CLI tool for automation. |
| **Active Exploitation Framework** | Out of scope. RedAudit is for *auditing* and *discovery*, not weaponized exploitation (like Metasploit). |
| **Native Windows Support** | Too complex due to raw socket requirements. Use WSL2 or Docker on Windows. |
| **PDF Report Generation** | Adds heavy dependencies (LaTeX/ReportLab). JSON/HTML output is preferred for modern workflows. |

---

## 4. Contributing

1. Check [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Read [CONTRIBUTING.md](../.github/CONTRIBUTING.md).
3. Open a Discussion before starting major features.

[Back to Documentation Index](INDEX.md)
