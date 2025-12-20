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

*(No high priority items currently pending)*

### Red Team Extensions (Priority: Medium)

*(No medium priority items currently pending)*

### Infrastructure (Priority: Low)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **PyPI Distribution** | 🚧 Deferred | Publishing `pip install redaudit`. Blocked by need for extensive cross-platform testing. |
| **Containerization** | 🚧 Deferred | Official Docker image. Deferred in favor of standard pip/venv installation stability. |
| **Plugin Engine** | 🚧 Deferred | "Plugin-first" architecture to decouple core scanner from tools. |

---

## 2. Implemented Capabilities (Verified)

Features currently present using `redaudit --version` >= v3.6.0.

### UX & Integrations (v3.7.0)

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Interactive Webhooks** | v3.7.0 | `redaudit/core/wizard.py`. Configure Slack/Teams directly in wizard. |
| **Advanced Net Discovery Wizard** | v3.7.0 | `redaudit/core/wizard.py`. Configure SNMP/DNS/Targets interactively. |
| **Native SIEM Pipeline** | v3.7.0 | `siem/`. Configs for Filebeat/Logstash + Sigma rules. |
| **Session Logging** | v3.7.0 | `redaudit/utils/session_log.py`. Captures terminal output to `.log` and `.txt`. |
| **Stable Progress (HyperScan/Nuclei)** | v3.7.2 | `redaudit/core/net_discovery.py`, `redaudit/core/auditor.py`, `redaudit/core/nuclei.py`. Avoids flicker and shows ETA. |

### Advanced Scanning & Automation

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Nuclei Integration** | v3.6.0 | Module `redaudit/core/nuclei.py`. Runs templates when Nuclei is installed and explicitly enabled (wizard or `--nuclei`). |
| **Agentless Verification** | v3.7.3 | `redaudit/core/agentless_verify.py`. Optional SMB/RDP/LDAP/SSH/HTTP fingerprinting (wizard or `--agentless-verify`). |
| **Playbook Generation** | v3.4.0 | Module `redaudit/core/playbook_generator.py`. Creates MD remediation guides in `playbooks/`. |
| **Red Team: Kerberos** | v3.2.0 | Module `redaudit/core/net_discovery.py`. Uses `kerbrute` for user enumeration if approved. |
| **Red Team: SNMP/SMB** | v3.2.0 | Module `redaudit/core/net_discovery.py`. Uses `snmpwalk` and `enum4linux`. |
| **SIEM Readiness** | v3.1.0 | Module `redaudit/core/siem.py`. Outputs ECS v8.11 compliant JSON/JSONL. |
| **Differential Analysis** | v3.3.0 | Module `redaudit/core/diff.py`. Visual HTML diff of two scans. |

### Core & Stability

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Single Version Source** | v3.5.4 | Version now resolves reliably across install modes: `importlib.metadata` when available, plus a packaged `redaudit/VERSION` fallback for script-based `/usr/local/lib/redaudit` installs. |
| **Centralized CommandRunner** | v3.5.0 | `redaudit/core/command_runner.py` handles all subprocesses safely. |
| **Timeout-Safe Host Scans** | v3.7.3 | `redaudit/core/auditor.py` enforces hard timeouts for nmap host scans, keeping progress responsive. |
| **Persistent Config** | v3.1.1 | `~/.redaudit/config.json` stores user defaults. |
| **Async Discovery** | v3.1.3 | `redaudit/core/hyperscan.py` uses `asyncio` for fast port probing. |
| **Quiet Progress UI (with detail)** | v3.6.0 | `redaudit/core/auditor.py` reduces terminal noise while progress bars are active and surfaces “what’s happening” inside the progress line. |

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
