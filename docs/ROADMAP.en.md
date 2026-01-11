# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ROADMAP.es.md)

**Audience:** Contributors, stakeholders
**Scope:** Planned features, verified capabilities, discarded concepts.
**Source of Truth:** Repository code and Git history

---

This document outlines the technical roadmap, verifies implemented capabilities, and records discarded approaches for RedAudit.

## 1. Active Roadmap (Upcoming Features)

These features are approved but **not yet implemented** in the codebase.

### v4.4 Code Coverage & Stability (Priority: High) ✅

| Feature | Status | Description |
| :--- | :--- | :--- |
| **100% Topology Coverage** | ✅ Done (v4.4.5) | Achieved complete test coverage for `topology.py` (route parsing, loop detection, graphing). |
| **>94% Updater Coverage** | ✅ Done (v4.4.5) | Hardened `updater.py` with robust tests for Git operations, rollback scenarios, edge-case failures. |
| **Project Coverage ~89%** | ✅ Done (v4.4.5) | Overall project coverage now at 88.75% (1619 tests passing). |
| **Memory Leak Fix** | ✅ Done (v4.4.5) | Fixed infinite loop in test mocks that caused 95GB RAM spike. |

### v4.3 Risk Score & Performance Improvements (Priority: High) ✅

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Weighted Maximum Gravity Algorithm** | ✅ Done | Refactored `calculate_risk_score()` to use CVSS scores from NVD data as primary factor. Formula: Base (max CVSS * 10) + Density bonus (log10) + Exposure multiplier (1.15x for external ports). |
| **Risk Score Breakdown Tooltip** | ✅ Done | HTML reports show detailed risk score components on hover (Max CVSS, Base Score, Density Bonus, Exposure Multiplier). |
| **Identity Score Visualization** | ✅ Done | HTML reports display color-coded identity_score with tooltip showing identity signals. |
| **Smart-Check CPE Validation** | ✅ Done | Enhanced Nuclei false positive detection using host CPE data before HTTP header checks. |
| **HyperScan SYN Mode** | ✅ Done | Optional scapy-based SYN scanning (`--hyperscan-mode syn`) for ~10x faster discovery. Auto-detection with fallback to connect mode. |
| **PCAP Management Utilities** | ✅ Done | `merge_pcap_files()`, `organize_pcap_files()`, `finalize_pcap_artifacts()` for post-scan cleanup. |

### v4.1 Performance Optimizations (Priority: High) ✅

Optimizations following the "fast discovery, targeted fingerprint" pattern:

| Feature | Status | Description |
| :--- | :--- | :--- |
| **HyperScan-First Sequential** | ✅ Done | Pre-scan all 65,535 ports per host sequentially before nmap. Avoids FD exhaustion. batch_size=2000. |
| **Parallel Vuln Scanning** | ✅ Done | Run nikto/testssl/whatweb concurrently per host. |
| **Pre-filter Nikto CDN** | ✅ Done | Skip Nikto on Cloudflare/Akamai/AWS CloudFront. |
| **Masscan Port Reuse** | ✅ Done | Pre-scan uses masscan ports if already discovered. |
| **CVE Lookup Reordering** | ✅ Done | CVE correlation moved after Vuln Scan + Nuclei. |

### v4.2 Pipeline Optimizations ✅ (Released in v4.2.0)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Enhanced Parallel Progress UI** | ✅ Done (v4.2.0) | Multi-bar Rich progress bars for Deep Scan and parallel phases. |
| **Web App Vuln Scan (sqlmap)** | ✅ Done (v4.1.0) | Integrated `sqlmap` with configurable level/risk in wizard. |
| **Web App Vuln Scan (ZAP)** | ✅ Done (v4.2.0) | Integrated OWASP ZAP for web app spidering. |
| **Parallel Deep Scan** | ✅ Done (v4.2.0) | Decoupled Deep Scan with up to 50 threads and multi-bar UI. |
| **Private MAC Indicator** | ✅ Done (v4.2.0) | Detects locally-administered MACs (bit 2 of first byte) and shows "(private MAC)". |
| **Deep Scan Separation** | ✅ Done (v4.2.0) | Deep Scan extracted from `scan_host_ports()` as independent phase `run_deep_scans_concurrent()`. |
| **Red Team → Agentless** | ✅ Done (v4.2.0) | SMB/LDAP findings from Red Team passed to Agentless Verify. |
| **Wizard UX: Phase 0 auto** | ✅ Done (v4.2.0) | Phase 0 auto-enabled in Exhaustive profile. |
| **Wizard UX: Custom** | ✅ Done (v4.2.0) | Improved Custom wizard with Masscan vs HyperScan choice. |
| **HyperScan naming cleanup** | ✅ Done (v4.2.0) | Functions renamed for clearer purpose. |
| **Session log detail** | ✅ Done (v4.2.0) | Session log enriched with more detail than cli.txt. |

### v4.0 Architecture Refactoring ✅ (Released in v3.10.2)

Internal refactoring using Strangler Fig pattern:

1. ✅ **Phase 1**: UIManager - Standalone UI operations class
2. ✅ **Phase 2**: ConfigurationContext - Typed configuration wrapper
3. ✅ **Phase 3**: NetworkScanner - Identity scoring utilities
4. ✅ **Phase 4**: Adapter properties for gradual migration

**Status**: Completed in v4.0.0. Composition-first orchestration via `AuditorRuntime`, with
legacy inheritance removed and compatibility handled by adapter-backed components.

### Infrastructure (Priority: High)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Test Suite Consolidation** | ✅ Done | Refactored 199 test files → 123 files. Created `conftest.py`. Removed 76 coverage-gaming artifacts. 1130 tests at 85% coverage. |

### Infrastructure (Priority: Low)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **PyPI Distribution** | 🚧 Deferred | Publishing `pip install redaudit`. Blocked by need for extensive cross-platform testing. |
| **Plugin Engine** | 🚧 Deferred | "Plugin-first" architecture to decouple core scanner from tools. |

### Phase 6: Enterprise Scalability (>50 Hosts) (Priority: Medium) ✅

Focus: Removing bottlenecks for large corporate networks.

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Generator-based Targeting** | ✅ Done | Switch from list-based targeting to generator-based streaming. prevents memory spike when loading large subnets (/16). |
| **Streaming JSON Report** | ✅ Done | Optimized `auditor_scan.py` host collection to avoid list materialization on large networks. |

| **AsyncIO Migration** | 🚧 Deferred | Full migration to AsyncIO deferred to v5.0 based on feasibility study. |
| **Smart-Throttle (Adaptive Congestion)** | ✅ Done | AIMD-based dynamic batch size adjustment (Smart-Throttle). Detects network stress/packet loss and auto-throttles scans to prevent DoS. [View Spec](design/smart_throttle_spec.md) |

### Phase 7: UX Polish & Cosmetics (Priority: Low)

Minor improvements identified during v4.4.0 Gold Master validation.

| Task | Status | Description |
| :--- | :--- | :--- |
| **P7.1 Progress Bar Completion** | Done (v4.6.8) | Stop updating vuln scan progress after a host finishes to prevent misleading movement. |
| **P7.2 Nikto Timeout Visibility** | Planned | Show "timeout" indicator instead of stalled progress when Nikto exceeds threshold. |
| **P7.3 Streaming JSON Report** | Planned | Incremental write for reports >500MB on very large networks. |
| **P7.4 Web Tag Backfill** | Done (v4.6.8) | Add the `web` tag when `web_ports_count` is present even if port flags are missing. |

---

## 2. Implemented Capabilities (Verified)

Features present in releases where `redaudit --version` >= v3.6.0, with verification paths in the codebase.

### v4.5 Authenticated Scanning (Phase 4)

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Secrets Management** | v4.5.0 | `redaudit/core/credentials.py`. Secure credential storage with Environment and Keyring backends. |
| **SSH Scanning** | v4.5.0 | `redaudit/core/auth_ssh.py`. Authenticated Linux enumeration (OS, Packages, Services) via Paramiko. |
| **SMB/WMI Scanning** | v4.5.0 | `redaudit/core/auth_smb.py`. Authenticated Windows enumeration (Shares, Users, OS) via Impacket. |
| **SNMP v3** | v4.5.0 | `redaudit/core/auth_snmp.py`. Secure network device auditing with Auth/Priv protocols. |
| **Lynis Integration** | v4.5.0 | `redaudit/core/auth_lynis.py`. Remote execution of CIS hardening audits via SSH. |
| **Multi-Credential Support** | v4.5.2 | `redaudit/core/credentials_manager.py`. Universal credential spraying with protocol auto-detection. |
| **Wizard Universal Auth** | v4.5.2 | `redaudit/core/wizard.py`. New `ask_auth_config` step supporting both Universal and Advanced auth modes. |

### UX & Integrations (v3.7.0+)

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **VPN Interface Detection** | v3.9.6 | `redaudit/core/entity_resolver.py`. Classifies VPN gateways via vendor OUI matching, VPN service ports (500/4500/1194/51820), and hostname patterns. |
| **IoT Signature Pack** | v3.9.5 | `redaudit/core/udp_probe.py`, `redaudit/core/hyperscan.py`. Protocol-specific UDP payloads for WiZ, Yeelight, Tuya/SmartLife, CoAP/Matter devices. |
| **Wizard Profile Selector** | v3.9.0 | `redaudit/core/auditor.py`. Express/Standard/Exhaustive auto-config presets + Custom wizard mode. |
| **Real Timing Modes** | v3.9.0 | `redaudit/core/scanner/nmap.py`, `redaudit/core/auditor_scan.py`. Timing modes apply nmap `-T1`/`-T4`/`-T5` templates with delay/thread adjustments. |
| **Enhanced HTML Reports** | v3.9.0 | `redaudit/templates/report*.html.j2`. Expandable findings with observations, smart scan analysis, playbooks grid, PCAP evidence, topology details. |
| **Nuclei False Positive Detection** | v3.9.0 | `redaudit/core/verify_vuln.py`. Server header vs vendor CPE mapping to flag suspected FPs (`suspected_false_positive` field). |
| **Status Color Consistency** | v3.8.4 | `redaudit/core/auditor.py`. Uses Rich console.print() when progress is active to ensure colors display correctly. |
| **Auditor Identity** | v3.8.3 | `redaudit/core/wizard.py`. Wizard prompt for auditor name, surfaced in TXT/HTML reports. |
| **Bilingual HTML Reports** | v3.8.3 | `redaudit/core/reporter.py`. When language is ES, `report_es.html` is generated alongside the default HTML report. |
| **Wizard Navigation** | v3.8.1 | `redaudit/core/wizard.py`. "<Go Back" option in wizard menus for step-by-step navigation. |
| **HTML Report Watermark** | v3.8.2 | `redaudit/templates/report.html.j2`. Professional footer with GPLv3, author, and GitHub link. |
| **Interactive Webhooks** | v3.7.0 | `redaudit/core/wizard.py`. Configure Slack/Teams directly in wizard. |
| **Advanced Net Discovery Wizard** | v3.7.0 | `redaudit/core/wizard.py`. Configure SNMP/DNS/Targets interactively. |
| **Native SIEM Pipeline** | v3.7.0 | `siem/`. Configs for Filebeat/Logstash + Sigma rules. |
| **Session Logging** | v3.7.0 | `redaudit/utils/session_log.py`. Captures terminal output to `.log` and `.txt`. |
| **Stable Progress (HyperScan/Nuclei)** | v3.7.2 | `redaudit/core/hyperscan.py`, `redaudit/core/auditor.py`, `redaudit/core/nuclei.py`. Avoids flicker and shows ETA. |

### Advanced Scanning & Automation

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Nuclei Integration** | v3.6.0 | Module `redaudit/core/nuclei.py`. Runs templates when Nuclei is installed and explicitly enabled (wizard or `--nuclei`). |
| **Agentless Verification** | v3.7.3 | `redaudit/core/agentless_verify.py`. Optional SMB/RDP/LDAP/SSH/HTTP fingerprinting (wizard or `--agentless-verify`). |
| **Quiet-Host HTTP Probe** | v3.8.5 | `redaudit/core/auditor_scan.py`, `redaudit/core/scanner/enrichment.py`. Short HTTP/HTTPS title+server probe on common ports for vendor-only hosts with zero open ports. |
| **Playbook Generation** | v3.4.0 | Module `redaudit/core/playbook_generator.py`. Creates MD remediation guides in `playbooks/`. |
| **Red Team: Kerberos** | v3.2.0 | Module `redaudit/core/net_discovery.py`. Uses `kerbrute` for user enumeration if approved. |
| **Red Team: SNMP/SMB** | v3.2.0 | Module `redaudit/core/net_discovery.py`. Uses `snmpwalk` and `enum4linux`. |
| **SIEM Readiness** | v3.1.0 | Module `redaudit/core/siem.py`. Outputs SIEM-friendly JSON/JSONL with ECS-aligned fields. |
| **Differential Analysis** | v3.3.0 | Module `redaudit/core/diff.py`. Visual HTML diff of two scans. |

### Core & Stability

| Feature | Version | Verification |
| :--- | :--- | :--- |
| **Single Version Source** | v3.5.4 | Version now resolves reliably across install modes: `importlib.metadata` when available, plus a packaged `redaudit/VERSION` fallback for script-based `/usr/local/lib/redaudit` installs. |
| **Container Image** | v3.8.4 | `Dockerfile` + `.github/workflows/docker.yml` publish a GHCR image for reproducible runs. |
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
| **Distributed Scanning** | Too complex (FastAPI/Redis). RedAudit is a tactical CLI tool, not a SaaS platform. Architecture rejected. |

---

## 4. Contributing

1. Check [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Read [CONTRIBUTING.md](../CONTRIBUTING.md).
3. Open a Discussion before starting major features.

[Back to Documentation Index](INDEX.md)
