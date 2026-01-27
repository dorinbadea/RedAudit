# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ROADMAP.es.md)

**Audience:** Contributors, stakeholders
**Scope:** Planned features, verified capabilities, discarded concepts.
**Source of Truth:** Repository code and Git history

---

This document outlines the technical roadmap, verifies implemented capabilities, and records discarded approaches for RedAudit.

## 1. Active Roadmap (Future & In-Progress)

These items represent the current backlog of planned or deferred work for the remaining v4.x series.

### v4.14 Dependency Management (Priority: Low)

| Feature | Status | Description |
| --- | --- | --- |
| **Dependency Pinning Mode** | Done (v4.18.8) | Optional toolchain pinning for GitHub-downloaded tools via `REDAUDIT_TOOLCHAIN_MODE` and version overrides. |
| **Poetry Lockfile Evaluation** | Done (v4.18.8) | Added `poetry.lock` alongside pip-tools for evaluation and workflow parity. |
| **Streaming JSON Report** | Planned | Incremental write for reports >500MB on very large networks to prevent OOM. |

### Deferred / Technical Backlog

| Feature | Status | Description |
| --- | --- | --- |
| **auditor.py Refactor** | Deferred | Split orchestration and decision logic only if it unlocks testing or fixes defects. |
| **PyPI Distribution** | Deferred | Publishing `pip install redaudit`. Blocked by need for extensive cross-platform testing. |
| **Plugin Engine** | Deferred | "Plugin-first" architecture to decouple core scanner from tools. |
| **AsyncIO Migration** | Deferred | Full migration to AsyncIO deferred to v5.0. |
| **Centralized Timeout Registry** | Deferred | Consolidate scanner timeouts in one place for easier tuning and testing. |
| **Red Team Module Split** | Done (v4.18.8) | Split Red Team discovery logic into a dedicated module to reduce `net_discovery.py` size. |

---

### Future Features (v5.0.0)

| Feature | Description |
| --- | --- |
| **Protocol Specific IoT Probes** | Deep queries for device-specific protocols (Tuya, CoAP, proprietary). |
| **Leak Following** | Automated scope expansion based on leaked internal headers. |
| **Pipeline Audit** | Interactive visualization of the discovery flow. |

---

## 2. Completed Milestones (History)

These items are ordered chronologically (most recent first).

### v4.19.5 Nuclei Resume Metadata Alignment (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Targets Restore** | Done (v4.19.5) | Resume runs now preserve target networks in report summaries/manifests. |
| **Resume Duration Preservation** | Done (v4.19.5) | Resume summaries retain total scan duration instead of resetting to zero. |

### v4.19.4 Nuclei Resume Budget Control (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Budget Override** | Done (v4.19.4) | Resume prompts let operators change or disable the saved runtime budget. |
| **CLI Resume Override** | Done (v4.19.4) | `--nuclei-max-runtime` applies when resuming from CLI. |
| **Budget-Aware Batching** | Done (v4.19.4) | Budget runs skip starting a new batch if remaining time cannot cover the estimated batch runtime. |

### v4.19.3 Audit Follow-ups (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **SNMP v3 Protocol Mapping** | Done (v4.19.3) | Auth/priv protocol names map to PySNMP objects and respect explicit auth/priv keys. |
| **SNMP Topology CVE Safety** | Done (v4.19.3) | SNMP topology processing no longer assumes an initialized NVD API key. |
| **WhatWeb Diff Alignment** | Done (v4.19.3) | Diff reports count WhatWeb findings using the correct key. |
| **Offline OUI /28 and /36** | Done (v4.19.3) | Offline manuf lookups resolve 28- and 36-bit prefixes. |
| **Nuclei Timeout Default** | Done (v4.19.3) | Configuration default matches the CLI 300s timeout. |
| **Docs Alignment Cleanup** | Done (v4.19.3) | ES timing presets, thread fallback, and Docker/Security docs align with policy. |

### v4.19.2 Nuclei Resume Progress (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Progress UI** | Done (v4.19.2) | Resume runs use the standard progress UI even when a runtime budget is set. |
| **Resume Sorting** | Done (v4.19.2) | Resume candidates are ordered by the latest update timestamp. |
| **Resume Warnings** | Done (v4.19.2) | Budget/timeout warnings are shown after resume runs with pending targets. |

### v4.19.1 Nuclei Budget Enforcement (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Budget Cap** | Done (v4.19.1) | Runtime budget caps batches to remaining time and saves pending targets mid-batch. |
| **Nuclei Budget UX** | Done (v4.19.1) | Progress detail uses status color and budget-only stops avoid timeout warnings. |

### v4.19.0 Nuclei Runtime Resume (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Runtime Budget** | Done (v4.19.0) | Optional runtime budget writes resume artifacts and keeps the scan moving. |
| **Nuclei Resume Flow** | Done (v4.19.0) | Resume from main menu or CLI, updating reports in the same scan folder. |

### v4.18.22 Nuclei Coverage Timeout Floor (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Timeout Floor** | Done (v4.18.22) | Split retries keep the configured batch timeout as a floor to preserve coverage on slow targets. |

### v4.18.21 Updater Home Refresh Safety (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Home Copy Backup** | Done (v4.18.21) | System updates back up dirty `~/RedAudit` copies and refresh documentation. |

### v4.18.20 Nuclei Resilience and UI Sync Refinement (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Parallel Clamp** | Done (v4.18.20) | Long Nuclei timeouts now clamp parallel batches to reduce full-scan timeouts. |
| **UI Language Resync** | Done (v4.18.20) | UI manager now updates when CLI language changes after initialization. |
| **ANSI Status Contrast** | Done (v4.18.20) | ANSI status lines now apply the status color to the full message text. |

### v4.18.19 UI Consistency and Snapshot Coverage (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **UI Language Sync** | Done (v4.18.19) | UI manager language now follows CLI language to prevent mixed EN/ES output. |
| **Progress Line Styling** | Done (v4.18.19) | Rich progress output applies status color to all message lines. |
| **Config Snapshot Fields** | Done (v4.18.19) | Report snapshots now include `deep_id_scan`, `trust_hyperscan`, and `nuclei_timeout`. |

### v4.18.18 Wizard Contrast and Low-Impact Enrichment (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Vendor-Only HTTP Probe** | Done (v4.18.18) | Phase 0 enrichment optionally probes HTTP/HTTPS when a host has vendor/MAC only and zero open ports. |
| **Wizard Default Contrast** | Done (v4.18.18) | Non-selected options render in blue and default values are highlighted in prompts. |
| **Nuclei Split Timeout Clamp** | Done (v4.18.18) | Split batches reduce timeout budgets to avoid long retries on slow targets. |

### v4.18.17 HyperScan Reporting Clarity (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **HyperScan Summary Alignment** | Done (v4.18.17) | HyperScan-First comparisons now track TCP-only discovery for CLI consistency. |
| **HyperScan UDP Count in Pipeline** | Done (v4.18.17) | Pipeline net discovery counts include total HyperScan UDP ports for report visibility. |

### v4.13 Resilience & Observability (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Dead Host Retries** | Done (v4.13.0) | New `--dead-host-retries` CLI flag to abandon hosts after N consecutive timeouts. |
| **Honeypot Detection** | Done (v4.9.1) | Heuristic tagging (`honeypot`) for hosts with excessive open ports (>100). |
| **No-Response Tagging** | Done (v4.9.1) | Distinct `no_response` tag for hosts that fail Nmap scanning. |
| **i18n Nuclei Time Estimates** | Done (v4.13.0) | Corrected wizard profile time estimates for fast/balanced profiles. |

### v4.12 Performance & Data Quality (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei 'Fast' Profile Optimization** | Done (v4.12.1) | Boosted speed (300 req/s) and batch size (15) for fast profile. |
| **OUI Vendor Enrichment** | Done (v4.12.1) | Fallback to online API for unknown vendors in network topology. |
| **Clarified 'Express' Wizard** | Done (v4.12.1) | Updated i18n to explicitly state "Discovery Only". |
| **Flexible Nuclei Config** | Done (v4.12.1) | Configurable `rate_limit` and `batch_size` per profile with override support. |
| **Escalation Reason Counters** | Done (v4.12.1) | Aggregated metrics on why deep scans were triggered (score, ambiguity). |

### v4.11 Performance & IoT Visibility (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Scan Profiles** | Done (v4.11.0) | `--profile` flag (full/balanced/fast) to control scan intensity and speed. |
| **IoT WiZ Detection** | Done (v4.11.0) | Specialized UDP probe (38899) for WiZ smart bulbs. |
| **OUI Database Expansion** | Done (v4.11.0) | Updated Macs to ~39k vendors (Wireshark ingest). |
| **Nuclei Batch Optimization** | Done (v4.11.0) | Reduced batch size (10) and increased timeouts (600s) for dense nets. |

### v4.10 Advanced Discovery (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **SNMP Router Query** | Done (v4.10.0) | Query router interfaces and remote ARP tables via `snmpwalk`. |
| **LLDP Discovery** | Done (v4.10.0) | Discover switch topology on managed networks via `lldpctl`. |
| **CDP Discovery** | Done (v4.10.0) | Cisco Discovery Protocol parsing for Cisco-based topologies. |
| **VLAN Tagging Detection** | Done (v4.10.0) | Detect 802.1Q tagged VLANs on the audit host interfaces via `ifconfig`/`ip link`. |

### v4.9 Hidden Network Detection (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Routed Network Discovery** | Done (v4.9.0) | Detect hidden networks via `ip route` and `ip neigh` parsing. |
| **Interactive Discovery Prompt** | Done (v4.9.0) | Wizard asks to include discovered routed networks in scope. |
| **CLI --scan-routed** | Done (v4.9.0) | Automated inclusion of routed networks for CI/CD pipelines. |
| **IoT UDP Port Visibility** | Done (v4.9.1) | Ensure specialized UDP ports (e.g., WiZ 38899) found by HyperScan are included in final reports. |
| **Honeypot Detection** | Done (v4.9.1) | Heuristic tagging (`honeypot`) for hosts with excessive open ports (>100). |
| **No-Response Tagging** | Done (v4.9.1) | Distinct `no_response` tag for hosts that fail Nmap scanning. |

### v4.8 RustScan and Installer Fixes (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **RustScan Full Port Range** | Done (v4.8.2) | Force `-r 1-65535` to scan all ports instead of RustScan's default top 1000. |
| **ARM64 Installer Support** | Done (v4.8.3) | Added ARM64/aarch64 detection for Raspberry Pi and Apple Silicon VMs. |
| **Nuclei Wizard Toggle** | Done (v4.8.1) | Restore interactive Nuclei enable prompt in Exhaustive profile. |

### v4.7 HyperScan Masscan Integration (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Masscan Backend** | Replaced (v4.8.0) | `masscan_scanner.py` replaced by `RustScan` for higher speed and accuracy. |
| **RustScan Integration** | Done (v4.8.0) | New primary module for HyperScan. Scans all ports in ~3s. |
| **Docker Network Fallback** | Done (v4.7.1) | Automatic Scapy fallback when Masscan returns 0 ports (Docker bridge networks). |
| **Nuclei Timeout Fix** | Done (v4.7.2) | Increased command_runner timeout to 600s for Nuclei (was 60s, causing batch timeouts). |
| **NVD API 404 Skip** | Done (v4.7.2) | Skip retries on 404 responses (CPE not found). Reduces log spam. |

### v4.6 Scan Fidelity & Time Control (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Infra-Aware Web App Gating** | Done | Skip sqlmap/ZAP on infrastructure UIs when identity evidence indicates router/switch/AP devices. |
| **Deep Scan Identity Evidence** | Done | HTTP title/server and device-type hints suppress deep scan when identity is already strong. |
| **Quick HTTP Identity Probe** | Done | Short HTTP/HTTPS probe on quiet hosts to resolve identity early. |
| **Nuclei Partial Reporting** | Done | Mark partial runs and record timeout/failed batch indexes in reports. |
| **Nuclei Batch Heartbeat** | Done (v4.6.11) | Keep progress updates during long batches to show activity and elapsed time. |
| **Nuclei Target Progress** | Done (v4.6.13) | Show target-based progress within batches to avoid frozen bars. |
| **Nuclei Progress Stability** | Done (v4.6.15) | Keep target progress monotonic across batch retries/timeouts. |
| **Nuclei Timeout Hardening** | Done (v4.6.16) | Adaptive batch timeouts and recursive splits to reduce partial runs. |
| **Sudo Keyring Context** | Done (v4.6.17) | Preserve DBus context when loading saved credentials under sudo. |
| **Host Report Alignment** | Done (v4.6.15) | Backfill host entries with unified asset names/interfaces for consistency. |
| **HTTP Identity Source Guard** | Done (v4.6.11) | Treat UPnP-only titles as hints and avoid forcing web scans or identity scoring. |
| **Wizard Target Normalization Summary** | Done (v4.6.13) | Show normalized targets with estimated host counts before execution. |
| **SSH Credential Spray** | Done (v4.6.18) | Try all credentials in spray list until success. Enables unified credential lists. |
| **Finding Prioritization** | Done (v4.6.19) | New `priority_score` (0-100) and `confirmed_exploitable` fields for better vulnerability ranking. |
| **Classic Backdoor Detection** | Done (v4.6.19) | Automatic banner detection for `vsftpd 2.3.4`, `UnrealIRCd 3.2.8.1`, and other known backdoors. |
| **Report Confidence Score** | Done (v4.6.19) | `confidence_score` (0.0-1.0) based on cross-validation (Nuclei+CVE) to reduce false positives. |
| **Improved Finding Titles** | Done (v4.6.19) | Descriptive titles ("SSL Hostname Mismatch", "Missing HSTS") with better fallback logic. |
| **Wizard Spray Counter** | Done (v4.6.19) | Display `(+N spray)` in credential summary for better visibility. |

### v4.4 Code Coverage & Stability (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **100% Topology Coverage** | Done (v4.4.5) | Achieved complete test coverage for `topology.py` (route parsing, loop detection, graphing). |
| **>94% Updater Coverage** | Done (v4.4.5) | Hardened `updater.py` with robust tests for Git operations, rollback scenarios, edge-case failures. |
| **Project Coverage ~89%** | Done (v4.4.5) | Overall project coverage at 88.75% (1619 tests passing). |
| **Memory Leak Fix** | Done (v4.4.5) | Fixed infinite loop in test mocks that caused 95GB RAM spike. |
| **Generator-based Targeting** | Done (v4.4.0) | Switch from list-based targeting to generator-based streaming. Prevents memory spikes when loading large subnets (/16). |
| **Streaming JSON Report** | Done | Optimized `auditor_scan.py` host collection to avoid list materialization on large networks. |
| **Smart-Throttle (Adaptive Congestion)** | Done (v4.4.0) | AIMD-based dynamic batch size adjustment (Smart-Throttle). Detects network stress/packet loss and auto-throttles scans. |

### v4.3 Risk Score & Performance Improvements (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Weighted Maximum Gravity Algorithm** | Done | Refactored `calculate_risk_score()` to use CVSS scores from NVD data as primary factor. |
| **Risk Score Breakdown Tooltip** | Done | HTML reports show detailed risk score components on hover. |
| **Identity Score Visualization** | Done | HTML reports display color-coded identity_score with tooltip showing identity signals. |
| **Smart-Check CPE Validation** | Done | Enhanced Nuclei false positive detection using host CPE data before HTTP header checks. |
| **HyperScan SYN Mode** | Done | Optional scapy-based SYN scanning (`--hyperscan-mode syn`) for ~10x faster discovery. |
| **PCAP Management Utilities** | Done | `merge_pcap_files()`, `organize_pcap_files()`, `finalize_pcap_artifacts()` for post-scan cleanup. |

### v4.2 Pipeline Optimizations (Released in v4.2.0)

See [Release Notes](../releases/RELEASE_NOTES_v4.2.0.md) for details.

### v4.1 Performance Optimizations (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **HyperScan-First Sequential** | Done | Pre-scan all 65,535 ports per host sequentially before nmap. Avoids FD exhaustion. |
| **Parallel Vuln Scanning** | Done | Run nikto/testssl/whatweb concurrently per host. |
| **Pre-filter Nikto CDN** | Done | Skip Nikto on Cloudflare/Akamai/AWS CloudFront. |
| **Masscan Port Reuse** | Done | Pre-scan uses masscan ports if already discovered. |
| **CVE Lookup Reordering** | Done | CVE correlation moved after Vuln Scan + Nuclei. |

### v4.0 Architecture Refactoring (Done)

Internal refactoring using Strangler Fig pattern. Completed in v4.0.0.

### Infrastructure (Priority: High)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Test Suite Consolidation** | Done | Refactored 199 test files → 123 files. Created `conftest.py`. Removed 76 coverage-gaming artifacts. 1130 tests at 85% coverage. |

---

## 3. Verified Capabilities Reference

Reference verification of key capabilities against the codebase.

| Capability | Version | Code Path / Verification |
| --- | --- | --- |
| **Passive LLDP Discovery** | v4.10.0 | `core/topology.py` (via `tcpdump` & `lldpctl`) |
| **Passive CDP Discovery** | v4.10.0 | `core/topology.py` (via `tcpdump`/CISCO-CDP) |
| **VLAN Tagging (802.1Q)** | v4.10.0 | `core/topology.py` (via `ip link`/`ifconfig`) |
| **WiZ IoT Probe (UDP)** | v4.11.0 | `core/udp_probe.py`, `core/auditor.py` |
| **Nuclei Profiles** | v4.11.0 | `core/nuclei.py`, `core/auditor.py` |
| **OUI Database** | v4.11.0 | `data/manuf` (38k+ vendors) |
| **Routed Network Discovery** | v4.9.0 | `core/net_discovery.py` (`ip route`/`ip neigh`) |
| **RustScan Integration** | v4.8.0 | `core/rustscan.py` |
| **Smart-Check** | v4.3.0 | `core/scanner/enrichment.py` (CPE/False Positive logic) |

---

## 4. Discarded Concepts

Ideas considered but rejected to maintain project focus.

| Proposal | Reason for Rejection |
| :--- | :--- |
| **Web GUI (Controller)** | Increases attack surface and dependency weight. RedAudit is designed as a headless CLI tool for automation. |
| **Active Exploitation Framework** | Out of scope. RedAudit is for *auditing* and *discovery*, not weaponized exploitation (like Metasploit). |
| **Native Windows Support** | Too complex due to raw socket requirements. Use WSL2 or Docker on Windows. |
| **PDF Report Generation** | Adds heavy dependencies (LaTeX/ReportLab). JSON/HTML output is preferred for modern workflows. |
| **Distributed Scanning** | Too complex (FastAPI/Redis). RedAudit is a tactical CLI tool, not a SaaS platform. Architecture rejected. |

---

## 5. Contributing

1. Check [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Read [CONTRIBUTING.md](../CONTRIBUTING.md).
3. Open a Discussion before starting major features.

[Back to Documentation Index](INDEX.md)
