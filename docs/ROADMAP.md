# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ROADMAP_ES.md)

This document outlines the technical roadmap, planned architectural improvements, and discarded approaches for RedAudit.

## Active Roadmap (Upcoming)

### High Priority & Security Features (v3.5+)

| Priority | Feature | Status | Description |
| :--- | :--- | :--- | :--- |
| **High** | **Native SIEM Pipeline** | 🎯 Planned | Direct exporters: custom Filebeat module (Elasticsearch ingest autoconfig), Sigma rule mapping for common findings (Nikto, CVE, weak ciphers). JSONL with full ECS (calculated risk_score, rule.id). Flag `--siem-pipeline elk\|splunk\|qradar`. |
| ~~Medium~~ | ~~Playbook Export~~ | ✅ **Implemented (v3.4.0)** | Markdown playbooks per finding (TLS, headers, CVE, web, ports). Auto-generated in `<output_dir>/playbooks/`. |
| **Low** | **Osquery Hardening Verification** | 🎯 Planned | Post-scan module that executes Osquery queries (via fleet or direct) on live hosts to validate detected configs (firewall, services). Merged in SIEM/HTML report for closed-loop. |

### Red Team Extensions (v3.5+)

| Priority | Feature | Status | Description |
| :--- | :--- | :--- | :--- |
| **Medium** | **Impacket Integration** | 🎯 Planned | Optional module `--redteam-deep` using Impacket (smbexec, wmiexec, secretsdump) on dummy credentials or detected null sessions. Generates PoC evidence to validate Blue Team detection (SMB signing, LAPS). |
| **Medium** | **BloodHound Auto-Collector** | 🎯 Planned | Execute SharpHound/BloodHound.py on live Windows hosts (via detected psexec/winrm). Import JSON to local Neo4j and generate common attack paths report (Kerberoast, AS-REProast). Helps Blue Team prioritize AD hardening. |
| **Medium** | **Nuclei Automation** | 🎯 Planned (v3.6) | Launch Nuclei on detected HTTP/HTTPS/services with community templates + option to load custom. Output merged in findings with PoC URLs. Enables simulating modern attacks and generating defensive Sigma rules. |
| **Low** | **Red Team Playbook Generation** | 🎯 Planned | For exploitable findings (e.g., high CVE, weak auth), generate automatic PoC scripts (Python/Impacket/Msfvenom suggestions) in evidence folder. Includes safeguards (labs only, `--dry-run`). Facilitates testing Blue Team controls (EDR, logging). |

### Developer Experience / Technical Debt

| Priority | Feature | Status | Description |
| :--- | :--- | :--- | :--- |
| **Medium** | **Containerization** | Paused | Official Dockerfile and Docker Compose setup for ephemeral audit containers. |
| **Medium** | **Centralized CommandRunner** | ✅ **Implemented (v3.5.0)** | Single module for external command execution: args as list (anti-injection), configurable timeouts, retries with backoff, secret redaction in logs, dry-run support. Refactors subprocess calls across the codebase. |
| **Medium** | **Full `--dry-run` Support** | ✅ **Implemented (v3.5.1)** | Propagate `--dry-run` flag to all modules so commands are printed but not executed (no external commands run). Depends on CommandRunner. Useful for auditing and debugging. |
| **Low** | **Silent Progress UI (ETA)** | ✅ **Implemented (v3.5.1)** | Replace periodic "heartbeat" clocking warnings with Rich progress bars where possible (clear bars + ETA), keeping the terminal output calm and operator-friendly. |
| **Low** | **Net Discovery Activity Indicator** | ✅ **Implemented (v3.5.2)** | Adds visible activity feedback during Net Discovery phases and reduces noisy logs while progress UI is active; ETA display is now timeout-aware (upper bound). |
| **Low** | **Output Folder Manifest** | ✅ **Implemented (v3.5.1)** | Add `run_manifest.json` to each output folder (when encryption is disabled) to provide counts + artifact list for reproducibility and SIEM pipelines. |
| **Low** | **Post-update Restart Required** | ✅ **Implemented (v3.5.2)** | After installing an update, RedAudit shows a large restart notice, waits for confirmation, and exits to ensure the next run loads the new version cleanly. |
| **Low** | **Single Version Source** | 🎯 Planned | Read version from `pyproject.toml` via `importlib.metadata` instead of manual `VERSION = "x.y.z"`. Prevents version drift across files. |
| **Low** | **TTY Autodetection** | 🎯 Planned | Auto-disable colors when stdout is not a TTY (pipes/CI). Flag `--no-color` already exists but behavior not fully implemented. |
| **Low** | **Interactive Webhook Config** | 🎯 Planned | Add webhook URL prompt to interactive wizard for advanced users. Currently webhook is CLI-only (`--webhook URL`). |
| **Low** | **Interactive HTML Report Config** | 🎯 Planned | Add "Generate HTML report?" prompt to interactive wizard. Currently HTML report is CLI-only (`--html-report`). |

## Future Targets (Deep Dives)

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

## Reference: Recently Implemented Capabilities

### Enhanced Network Discovery (v3.2)

**Overview**: Detect guest networks, hidden VLANs, and additional DHCP servers not visible from the primary network segment.
Features allow detecting:

- ✅ DHCP discovery & Fping sweeps
- ✅ NetBIOS/mDNS/Bonjour/UPNP discovery
- ✅ Red Team recon (SNMP/SMB/RPC/LDAP/Kerberos/DNS)
- ✅ VLAN candidate analysis & passive L2 captures

**Standard Discovery Tools**:

| Technique | Tool |
| :--- | :--- |
| **DHCP Discovery** | `nmap --script broadcast-dhcp-discover` |
| **NetBIOS/mDNS/UPNP** | `nbtscan`, `avahi-browse`, `nmap` |
| **Netdiscover** | `netdiscover -r <range> -P` |

**Red Team Techniques (Guarded/Optional)**:

| Technique | Tool | What It Detects |
| :--- | :--- | :--- |
| **SNMP Walking** | `snmpwalk -v2c -c public` | Switch ports, VLANs |
| **SMB Enum** | `enum4linux`, `crackmapexec` | Users, shares, policies |
| **VLAN/STP/HSRP** | `tcpdump` | Passive L2 topology hints |
| **IPv6 Discovery** | `ping6`, `ip -6 neigh` | IPv6 neighbors |
| **Kerberos/LDAP** | `nmap` scripts | AD structure, realms |

**CLI Examples**:

```bash
redaudit --net-discovery --target 192.168.0.0/16 --yes
redaudit --net-discovery --redteam --target 10.0.0.0/8
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

**Status**: ✅ Implemented (v3.1.1)
**Concept**: User configuration in `~/.redaudit/config.json` overrides defaults (threads, output, rate-limit, UDP, topology, lang). YAML import/export remains a future enhancement.

## Completed Milestones

### v3.5.0 (Release - December 2025) -> **CURRENT**

*Minor release focused on reliability during long scans and safer external command execution.*

- [x] **Prevent sleep during scans**: Best-effort system/display sleep inhibition while a scan is running (opt-out with `--no-prevent-sleep`).
- [x] **Centralized CommandRunner**: Unified execution of external tools with timeouts, retries, secret redaction, and incremental `--dry-run` rollout.
- [x] **Dry-run improvements**: More modules respect `--dry-run`, with clear documentation that rollout is incremental.

### v3.4.4 (Hotfix - December 2025)

*Patch release focused on smoothing the defaults flow and update UX.*

- [x] **Defaults UX**: "Use defaults and continue" applies defaults correctly; starting immediately avoids re-asking scan parameters and can reuse saved targets when available.
- [x] **Update note**: Added guidance to restart the terminal or run `hash -r` when the banner version does not refresh after updating.

### v3.4.3 (Hotfix - December 2025)

*Patch release focused on improving finding readability and smoothing wizard defaults.*

- [x] **Descriptive finding titles**: Web findings now get a short `descriptive_title` derived from parsed observations (improves playbook headings, webhooks, and HTML readability).
- [x] **Wizard output directory default**: When the wizard would default under `/root/...`, RedAudit now prefers the user’s `Documents` folder (invoking user under `sudo`, and a single detected `/home/<user>` when running as root without `sudo`).
- [x] **Wizard selection marker**: Uses an ASCII `>` marker for maximum terminal compatibility.

### v3.4.2 (Hotfix - December 2025)

*Patch release focused on correcting persisted output defaults under `sudo` in the interactive wizard.*

- [x] **Wizard output_dir migration**: If an older persisted default points to `/root/...`, RedAudit automatically rewrites it to the invoking user’s `Documents` directory under `sudo`.

### v3.4.1 (Hotfix - December 2025)

*Patch release focused on saving reports under the invoking user when running with `sudo`.*

- [x] **Default output under sudo**: Default output resolves to the invoking user’s `Documents` directory (instead of `/root`).
- [x] **Sudo-aware `~` expansion**: `--output ~/...` and persisted defaults expand against the invoking user.
- [x] **Ownership hardening**: Best-effort `chown` of report output folder tree to avoid root-owned artifacts under the user’s home.
- [x] **Unit tests**: Added coverage for path resolution logic.

### v3.4.0 (Completed - December 2025)

*Feature release focused on remediation playbooks and documentation alignment.*

- [x] **Remediation Playbooks**: Auto-generated Markdown playbooks per host/category in `<output_dir>/playbooks/` (TLS, HTTP headers, CVE remediation, web hardening, port hardening).
- [x] **Integration**: Playbooks generated automatically after scan completion (no CLI flag; skipped when `--encrypt` is enabled).
- [x] **Testing**: Unit tests added for playbook generator.
- [x] **Docs refresh**: README, manuals, usage, didactic guides, troubleshooting, security docs, changelogs, release notes updated and made consistent.

### v3.3 (Completed - December 2025)

*Feature release focused on SIEM alerting, Blue Team dashboards, and visual diff output.*

- [x] **Webhook Realtime Alerting**: `--webhook URL` sends critical findings (high CVE, exposed services) via POST JSON to Slack/Teams/PagerDuty/TheHive during scan.
- [x] **Interactive HTML Dashboard**: Auto-generated HTML report (Jinja2 + Chart.js) with sortable tables, severity charts, and top ports. Flag `--html-report`.
- [x] **Diff Visual & Longitudinal Tracking**: Comparative HTML output for `--diff` (side-by-side, highlight new/resolved). JSONL differential export for historical SIEM.

### v3.2.2 (Completed - December 2025)

*Release focused on UX polish, Interactive Main Menu, and Topology Streamlining.*

- [x] **Interactive Main Menu**: Unified entry point for Scan, Update, Diff, and Exit.
- [x] **Streamlined Topology**: Simplified wizard for topology vs full scan.
- [x] **Non-TTY Support**: Better CI/Pipeline compatibility (no colors/spinners).
- [x] **Consolidated Defaults**: "Base Values" handling and cleaner persistence.
- [x] **Full i18n**: Completed translation of all CLI prompts and menus.

### v3.2.0 (Completed - December 2025)

*Feature release focused on enhanced network discovery (standard + optional Red Team recon), with full documentation alignment.*

- [x] **Enhanced Net Discovery**: `--net-discovery` adds DHCP/NetBIOS/mDNS/UPNP/ARP/fping discovery with VLAN candidate analysis.
- [x] **Red Team recon (guarded)**: Optional SNMP/SMB/RPC/LDAP/Kerberos/DNS enumeration and L2 passive captures behind `--redteam`.
- [x] **New CLI tuning flags**: Interface selection + safe limits (`--net-discovery-interface`, `--redteam-max-targets`, etc.).
- [x] **Report schema docs updated**: `net_discovery` and `redteam` blocks documented for v3.2.

### v3.1.4 (Completed - December 2025)

*Patch release focused on output quality improvements for maximum SIEM/AI scoring.*

- [x] **Descriptive finding titles**: Human-readable titles based on finding type (e.g., "Missing X-Frame-Options Header" instead of generic "Finding on URL").
- [x] **Nikto cross-validation**: `detect_nikto_false_positives()` compares findings with curl/wget headers to identify contradictions.
- [x] **RFC-1918 severity adjustment**: Internal IP disclosure on private networks now correctly rated as "low" severity.
- [x] **OS fingerprint extraction**: New `extract_os_detection()` function for structured OS info from Nmap output.
- [x] **Relative PCAP paths**: Reports use portable relative paths for PCAP files.
- [x] **Configurable TestSSL timeout**: Increased default from 60s to 90s with configurable parameter.
- [x] **Schema version constant**: Separate `SCHEMA_VERSION` constant for report versioning clarity.

### v3.1.3 (Completed - December 2025)

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
