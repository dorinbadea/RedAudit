# Changelog

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ES/CHANGELOG_ES.md)

All notable changes are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes live under `docs/releases/` for additional context.

## [Unreleased]

## [3.10.2] - 2026-01-04 (Auditor Node & MAC Display Fix)

### Added

- **Auditor Node Detection**: Scanner's own network interfaces are now marked as `(Auditor Node)` / `(Nodo Auditor)` in HTML reports instead of `-` for MAC column.
- **Architecture Foundation (Internal)**: Preparatory work for v4.0 modular architecture:
  - `UIManager` standalone class for UI operations
  - `ConfigurationContext` typed wrapper for configuration
  - `NetworkScanner` with identity scoring utilities
  - Adapter properties for backward compatibility

### Fixed

- **MAC Address Display**: Fixed bug where MAC addresses were not showing in HTML reports despite being captured correctly. Root cause: key mismatch (`host.get("mac")` vs `host.get("mac_address")`).

### Documentation

- VPN Vendor OUI Detection heuristic documentation
- Subnet Leak wording updated to "Network Leak Hints"
- Added missing CLI flags to README tables

## [3.10.1] - 2026-01-02 (Identity Consistency & Vendor Hints)

### Added

- **Vendor Hints**: New fallback mechanism (`vendor_hints.py`) to infer device manufacturer from hostname patterns (e.g., Pixel, Galaxy, iPhone) when OUI lookup is unavailable.

### Fixed

- **Neighbor Cache Enrichment**: MAC addresses discovered via passive neighbor cache (ARP/NDP) now trigger an online OUI vendor lookup.
- **Hostname Consistency**: Consolidated Phase 0 (low-impact) DNS reverse lookups into the canonical host record, ensuring consistent hostname display across all reports (HTML/TXT) and entity resolution logic.
- **Data Flow**: Fixed gaps where low-impact enrichment data was not fully propagating to downstream consumers.

## [3.10.0] - 2026-01-01 (SmartScan Governance & Phase0)

### Added

- **Phase0 low-impact enrichment (opt-in)**: Optional, short-timeout probes for reverse DNS, mDNS, and SNMP sysDescr to strengthen identity signals.
- **SmartScan governance controls**: Identity threshold and deep scan budget flags to keep escalation conservative by default.
- **Wizard support for Phase0**: Express, Standard, Exhaustive, and Custom flows can enable low-impact enrichment with persisted defaults.

### Changed

- **SmartScan escalation gating**: Deep scans trigger only when identity is weak relative to the configured threshold.
- **UDP priority reorder**: Applies only for low-identity hosts with minimal TCP visibility; never in stealth mode.

### Fixed

- **Deep scan budget under concurrency**: Thread-safe reservation prevents over-executing budgeted deep scans.
- **Phase0 DNS fallback**: Avoids global socket timeout side effects when `dig` is unavailable.
- **CLI help localization**: New flag help strings reflect selected language.

## [3.9.9] - 2025-12-29 (Printer Heuristic Fix)

### Fixed

- **Printer hostname detection**: Printer tokens now take precedence over workstation brand hints.

## [3.9.8] - 2025-12-29 (Discovery Identity Tuning)

### Fixed

- **Hostname suffix normalization**: Asset typing no longer depends on local DNS suffixes (e.g., `.fritz.box`).
- **Samsung classification**: Defaults to media unless explicit mobile indicators are present.
- **Router vendors**: Sercomm/Sagemcom now map to router/CPE devices.

### Improved

- **HTTP/agentless hints**: Device-type hints (router/repeater/access point) influence asset typing.
- **Android cast devices**: Hosts with cast/SSDP signals now classify as media.
- **Workstation hints**: Brand hostnames (MSI/Dell/Lenovo/HP/Asus/Acer) override RDP server heuristic.
- **Repeater fingerprint**: Added FRITZ!Repeater HTTP pattern for router detection.

## [3.9.7] - 2025-12-29 (Audit Quality Hotfix)

### Fixed

- **Nuclei false positives**: Suspected FPs are filtered before merging into findings, with counts exposed in the nuclei summary.
- **Web vuln counts**: Summary/manifest now expose raw vs consolidated counts to prevent CLI vs report mismatches.
- **JSONL findings titles**: Added `descriptive_title` to findings.jsonl for richer downstream display.

### Improved

- **Dynamic OS banner**: CLI banner now reflects the detected OS name with a safe `LINUX` fallback.

## [3.9.6] - 2025-12-28 (VPN Interface Detection)

- **VPN Interface Detection**: New heuristic to classify VPN gateway interfaces:
  - Same MAC as gateway + different IP = VPN virtual IP
  - VPN service ports (500, 4500, 1194, 51820) = IPSec/OpenVPN/WireGuard endpoint
  - Hostname patterns (vpn, ipsec, wireguard, tunnel) = VPN device
  - New `vpn` asset type with `vpn-endpoint` SIEM tag

## [3.9.5a] - 2025-12-28 (Installer & Tooling)

### Added

- **Installer: Web Analysis Tools**: Added `whatweb`, `nikto`, and `traceroute` to the apt package list for complete web vulnerability analysis out-of-the-box.

### Fixed

- **Installer: testssl.sh reliability**: Removed strict commit hash verification that was causing installation failures. Now uses version tag `v3.2` with automatic fallback to latest HEAD if the tag is unavailable.
- **CI: test_fping_sweep_logic**: Fixed mock target to properly simulate `fping` unavailability in GitHub Actions runner (mocks `shutil.which` + `_run_cmd` instead of `CommandRunner`).
- **Coverage Badge**: Replaced broken dynamic Gist badge with static 84% coverage badge.

## [3.9.5] - 2025-12-28 (IoT Signature Pack + NVD Hotfix)

### Added

- **IoT Signature Pack**: Protocol-specific UDP payloads for smart home device detection:
  - **WiZ bulbs** (port 38899): JSON registration method payload
  - **Yeelight** (ports 1982, 55443): Discovery command payload
  - **Tuya/SmartLife** (ports 6666, 6667): Protocol-aware probes
  - **CoAP/Matter** (port 5683): GET .well-known/core payload
- **Reverse DNS Hostname Fallback**: HTML reports now show IoT device hostnames from DNS reverse lookup when standard hostname is empty

### Fixed

- **NVD Product Names**: Relaxed regex sanitization in CVE lookup to preserve dots in product names (e.g., `node.js` is no longer stripped to `nodejs`), fixing CPE generation for many frameworks.

## [3.9.4] - 2025-12-28 (Net Discovery Parsing Hotfix)

### Fixed

- **DHCP domain hints**: Domain Name/Domain Search parsing now tolerates Nmap prefixes (`|`, `|_`, indentation) so internal domains are captured reliably.
- **NetBIOS names**: Nmap nbstat parsing now trims trailing punctuation to avoid inventory noise (e.g., `SERVER01,`).

## [3.9.3] - 2025-12-27 (Reporting Consolidation Hotfix)

### Fixed

- **Consolidated findings keep TestSSL data**: merged entries now preserve `testssl_analysis` and related observations to avoid losing TLS warnings in reports.
- **HTML titles for tool-only findings**: when a finding lacks `descriptive_title`, HTML now derives a meaningful title (e.g., `Web Service Finding on Port 443`) instead of a raw URL.

## [3.9.2] - 2025-12-27 (Version Detection Hotfix)

### Fixed

- **Script install version detection**: Accepts letter suffixes like `3.9.1a` in `redaudit/VERSION` to avoid `0.0.0-dev` after auto-update.

## [3.9.1a] - 2025-12-27 (Reporting Hotfix)

### Fixed

- **Spanish HTML report titles**: Regex matching now correctly localizes common finding titles in `report_es.html`.
- **summary.json metadata**: Added `scan_mode_cli`, compact `options`, and `severity_counts` alias to improve dashboard consumers.

## [3.9.0] - 2025-12-27 (Profile Selector & Enhanced Reports)

### Added

- **Wizard Profile Selector**: New first-step question to choose audit type:
  - **Express** — Fast discovery scan, minimal questions
  - **Standard** — Balanced scan with vulnerability analysis
  - **Exhaustive** — Maximum discovery, auto-configures everything:
    - Mode: `completo`, Threads: `MAX`, UDP: `full (500 ports)`
    - Vulnerabilities + Nuclei + Topology + Net Discovery + Red Team + Windows Verify
    - NVD CVE correlation enabled if API key is configured
  - **Custom** — Full 8-step wizard for complete control

- **Wizard Navigation**: "< Go Back" option from timing selector returns to profile selection.

- **Real Timing Differences**: Timing modes now have actual effect on nmap:
  - **Stealth** — nmap `-T1` (paranoid) + 2s delay + 2 threads (IDS evasion)
  - **Normal** — nmap `-T4` (aggressive) + no delay + default threads
  - **Aggressive** — nmap `-T5` (insane) + no delay + MAX threads

- **NVD API Key Reminder**: Wizard shows a reminder with link to get API key when CVE correlation is skipped.

- **Enhanced HTML Report** (for professional auditors):
  - **Expandable Findings**: Click any finding row to see technical observations (`parsed_observations`)
  - **Smart Scan Analysis Section**: Shows exactly why deep scans were triggered (e.g., `suspicious_service`, `many_ports`)
  - **Remediation Playbooks Section**: Visual grid of generated playbooks with target IPs
  - **Captured Evidence Section**: Lists all captured PCAP files
  - **Topology Summary**: Default gateway, interfaces count, routes count
  - Both English and Spanish templates updated

- **Session Log Filtering**: Smarter noise reduction preserves status messages while filtering spinner updates.

### Fixed

- **nmap timing not applied**: `nmap_timing` config was not passed to `get_nmap_arguments()`, so Stealth/Normal/Aggressive had no effect on actual nmap execution.
- **Playbooks not in HTML report**: Playbooks were generated AFTER HTML report, resulting in empty playbooks section. Now generated before HTML.

### Changed

- Default profile selection is "Standard" (index 1)
- Express profile skips timing question (always fast)
- `save_playbooks()` now returns `(count, playbook_data)` tuple for HTML integration

### Removed

- **prescan.py**: Dead code module superseded by `hyperscan.py` which includes TCP/UDP/ARP/IoT discovery.

## [3.8.9] - 2025-12-25 (Device Fingerprinting Export Fix)

### Fixed

- **Device fingerprinting fields now exported**: `device_vendor`, `device_model`, `device_type` are now included in `assets.jsonl` output and `agentless_hints` signals.
  - Previously these fields were extracted but filtered out during JSONL export.

## [3.8.8] - 2025-12-25 (Device Fingerprinting & UX)

### Added

- **HTTP Device Fingerprinting**: Automatic vendor/model identification from web interface titles.
  - 40+ device patterns: Vodafone, FRITZ!Box, TP-Link, NETGEAR, ASUS, Linksys, D-Link, Ubiquiti, MikroTik, Cisco, Hikvision, Dahua, Axis, Philips Hue, Synology, QNAP, and more.
  - New fields in agentless fingerprint: `device_vendor`, `device_model`, `device_type`.
  - Improves asset identification when hostname/MAC vendor is unavailable.

### Fixed

- **CLI Output Noise**: Reduced spinner update frequency from 10Hz to 4Hz (`refresh_per_second=4`).
  - Fixes excessive log file sizes when terminal is captured externally (e.g., `script` command).
  - Applied to all 9 Progress bars across auditor, hyperscan, nuclei modules.

## [3.8.7] - 2025-12-23 (Reporting & Classification Fixes)

### Fixed

- **Quiet-host identity**: HTTP identity probe now inspects meta titles and common logo alt text when login pages lack a title/heading.
- **Vuln source summary**: Pipeline vulnerability sources are inferred from tool-specific signals when explicit source is missing.
- **Host status**: Hosts with open ports are now marked `up` even when MAC/vendor data is present.
- **Asset type**: Chromecast/cast fingerprints map to `media`, Android OS hints map to `mobile`, and topology default gateway is tagged as `router` for entity resolution.

### Documentation

- Refreshed system architecture diagrams (EN/ES) to reflect current pipeline modules.
- Updated manuals (EN/ES) to clarify HTTP identity meta/title fallback for quiet hosts.

## [3.8.6] - 2025-12-22 (Docker Build Fix)

### Fixed

- **Docker build**: Install build tools in the image so `netifaces` compiles during `pip install`.
- **Quiet-host identity**: HTTP title probe now falls back to H1/H2 headings when `<title>` is missing, improving model detection on login pages.

### Documentation

- Added EN/ES language badges to release notes for v3.8.4 and v3.8.5.

## [3.8.5] - 2025-12-22 (Quiet-Host Identity)

### Added

- **Quiet-host HTTP probe**: Short HTTP/HTTPS title+server probe on common ports when a host has vendor hints but zero open ports, to improve model identification.

### Fixed

- **Asset classification**: Prefer device-specific hostname matches (e.g., `iphone`, `msi`) before router suffixes like `fritz` to reduce misclassification.
- **Asset naming**: Use HTTP title hints to label assets without hostnames and classify switch models from vendor/title cues.

### Documentation

- Updated manuals and report schema to describe the HTTP probe hints.

## [3.8.4] - 2025-12-21 (Agentless Verification & Color Fix)

### Added

- **Agentless verification**: Optional SMB/RDP/LDAP/SSH/HTTP fingerprinting stage (wizard or `--agentless-verify`), with a configurable target cap.
- **CLI flags**: `--agentless-verify`, `--no-agentless-verify`, and `--agentless-verify-max-targets`.

### Fixed

- **Status colors during progress**: Fixed `[INFO]` messages appearing without color when Rich Progress bar is active. Now uses Rich console.print with proper markup (`bright_blue` for INFO, `green` for OK, `yellow` for WARN, `red` for FAIL) ensuring consistent color display at all times.

## [3.8.3] - 2025-12-21 (Wizard & Reporting UX)

### Added

- **Auditor identity**: Wizard prompt for auditor name, surfaced in TXT/HTML reports.
- **Bilingual HTML**: When language is ES, `report_es.html` is generated alongside the default HTML report.

### Fixed

- **Wizard duplication**: Removed duplicate wording in vulnerability scan options (yes/no prompt).
- **Progress detail colors**: Status detail now respects INFO/WARN/FAIL colors while progress is active.
- **Net Discovery progress**: Prevents long phases from showing a stuck 100% before the final step completes.

### Changed

- **HTML footer**: Neutralized footer branding (license + GitHub) without personal author credit.

## [3.8.2] - 2025-12-20 (UX Polish)

### Added

- **HTML Watermark**: Professional footer in HTML reports with GPLv3 license, author (Dorin Badea), and GitHub link.

### Fixed

- **Spinner Removed**: Eliminated spinner from progress bars (was causing display freezes during long phases); now shows clean bar + percentage + elapsed time.

## [3.8.1] - 2025-12-20 (Visual Feedback Fix)

### Added

- **Wizard Navigation**: New `ask_choice_with_back` function adds "< Go Back" option to wizard menus, enabling step-by-step navigation without restarting the entire configuration.

### Fixed

- **ETA Removed**: Eliminated unreliable ETA estimates from progress bars (were freezing or showing incorrect values); now displays elapsed time only.
- **Progress Bar Truncation**: Fixed text truncation issue where long descriptions made progress bars unreadable (`Escaneado 192.168.178… ETA≤ …`).
- **Heartbeat Messages**: Added periodic heartbeat messages every 30-60s during long phases (Net Discovery, Host Scan) to indicate activity.
- **Device Type Detection**: Improved `device_type_hints` detection—added AVM/Fritz to router patterns, hostname-based mobile detection (iPhone, iPad, Android).

### Changed

- **Progress Display**: Simplified progress columns to: spinner + description + bar + percentage + elapsed time.
- **Net Discovery Labels**: Truncated phase labels to 35 characters to prevent overflow.

## [3.8.0] - 2025-12-20 (Net Discovery UX)

### Added

- **Net Discovery Progress Bar**: Replaced generic spinner with full Rich progress bar showing percentage, phase description, and ETA during network discovery (~10 min phase now shows real progress).
- **SmartScan Device Detection**: Automatic device type classification from vendor/UPNP/mDNS/service signatures (mobile, printer, router, IoT, smart_tv, hypervisor).
- **SmartScan Topology Signals**: Identity scoring now includes net_discovery results (ARP, UPNP, mDNS) for better deep scan decisions.
- **Wizard UX Hints**: Added examples to SNMP community, DNS zone, and webhook URL prompts.

### Changed

- **HyperScan Throttling**: Reduced progress update threshold from 3% to 1% and interval from 0.35s to 0.25s for smoother, more responsive feedback during parallel discovery.
- **SmartScan Full Mode**: Full scan mode no longer disables deep scan heuristics; instead uses higher identity threshold (4 vs 3) for more thorough discovery.
- **SmartScan Network Infrastructure**: Routers and network devices now always trigger deep scan for complete infrastructure mapping.

## [3.7.3] - 2025-12-20 (Scan Reliability & Reporting Accuracy)

### Fixed

- **Nmap XML parsing**: Preserve full XML output and extract the `<nmaprun>` block to prevent parse errors that masked
  host identities.
- **Timeout fallback**: When no host timeout is specified, fallback now respects scan mode (full/completo = 300s) to
  avoid premature timeouts.
- **Topology identity fallback**: If Nmap fails, MAC/vendor data from topology/neighbor cache is used to keep host
  identity in reports.
- **Report counts**: "Hosts Discovered" now deduplicates targets so it matches the unique host set.

## [3.7.2] - 2025-12-19 (UX & Progress Hotfix)

### Fixed

- **Net Discovery (HyperScan)**: Throttled progress updates to reduce flicker in terminals.
- **Nuclei UX**: Nuclei template scanning now reports progress/ETA without competing Rich Live displays.
- **Wizard Defaults UX**: If you choose "Review/modify" and skip the defaults summary, RedAudit no longer asks to start
  immediately with those defaults.
- **Wizard Net Discovery Prompts**: Clarified "ENTER uses default / ENTER to skip" for SNMP community and DNS zone.

## [3.7.1] - 2025-12-18 (Critical Hotfix)

### Fixed

- **Session Logging**: `TeeStream.encoding` changed from method to `@property` to fix Rich console crash.
- **Deep Scan**: Fixed `TypeError: can't concat str to bytes` in `output_has_identity()` by ensuring stdout/stderr are decoded.
- **HyperScan Progress**: Now uses `hyperscan_with_progress` wrapper in net_discovery for visible spinner.

## [3.7.0] - 2025-12-18 (Wizard UX & SIEM Integration)

### Added

- **Interactive Webhooks**: Wizard now prompts for Slack/Teams/PagerDuty webhook URL with optional test alert.
- **Advanced Net Discovery Wizard**: SNMP community string, DNS zone, and max targets now configurable via wizard.
- **Native SIEM Pipeline**: Bundled `siem/filebeat.yml`, `siem/logstash.conf`, and 3 Sigma rules for ELK and other SIEMs.
- **Osquery Verification**: New `redaudit/core/osquery.py` module for post-scan host config validation via SSH.
- **Session Logging**: Terminal output automatically captured to `session_logs/` folder (raw `.log` + clean `.txt`).
- **Nuclei Progress Spinner**: Animated Rich spinner with elapsed time during Nuclei template scans.

### Fixed

- **CodeQL CI**: Downgraded `codeql-action` to v3 for compatibility.

### Changed

- **Webhook config**: Now persisted in `~/.redaudit/config.json` alongside other defaults.

## [3.6.1] - 2025-12-18 (Scan Quality & UX)

### Added

- **Findings Consolidation**: Duplicate findings on same host (e.g., "Missing X-Frame-Options" on 5 ports) are now merged into single entries with `affected_ports` array.
- **OUI Fallback Lookup**: New `redaudit/utils/oui_lookup.py` module for online MAC vendor lookup via macvendors.com when local database is incomplete.
- **HTTPS Port Detection**: Expanded SSL/TLS detection to include common non-standard ports (8443, 4443, 9443, 49443).

### Fixed

- **Nuclei Integration Bug**: `get_http_targets_from_hosts()` was checking for `state != "open"` but RedAudit ports don't have a `state` field. Now uses `is_web_service` flag correctly.
- **Progress Bar Noise**: Condensed nmap command output from full command to `[nmap] IP (scan type)` for cleaner terminal display.
- **False Positive Handling**: When cross-validation detects Nikto reported a missing header that curl/wget shows as present, severity is now degraded to `info` with `verified: false`.

### Changed

- **testssl Execution**: Now runs on all HTTPS ports (8443, 49443, etc.), not just port 443.

## [3.6.0] - 2025-12-18 (Nuclei Enablement & UX)

### Added

- **Nuclei opt-in**: Nuclei templates can be enabled via the wizard or CLI (`--nuclei` / `--no-nuclei`) and saved as a persistent default.
- **More informative progress**: Host/vuln progress bars now surface “what’s happening” inside the progress line (without flooding the terminal).
- **Persistent Net Discovery defaults**: Net Discovery / Red Team choices (including L2 active and Kerberos user enum prompts) can be saved and reused.

### Changed

- **Installer UX**: The installer now displays the real RedAudit version (read from `redaudit/VERSION`) instead of a hard-coded value.

### Fixed

- **Quieter host scan phase**: Reduced noisy `[nmap]` / `[banner]` status spam while progress UI is active.

## [3.5.4] - 2025-12-18 (Hotfix)

### Fixed

- **Version detection in system installs**: Script-based installs under `/usr/local/lib/redaudit` now report the correct semantic version (no more `v0.0.0-dev` loops in the updater).

## [3.5.3] - 2025-12-18 (Documentation & Quality)

### Highlights

- **Documentation Integrity**: "Smoke-free" documentation that matches the codebase structure and features.
- **Roadmap Truth**: Strict separation of Planned vs Implemented features (verified against code).
- **Instructor Resources**: New pedagogical `DIDACTIC_GUIDE` (EN/ES) focused on teaching methodology.

### Fixed

- **Broken Links**: Fixed `pyproject.toml` pointing to non-existent `docs/MANUAL.md`.
- **Structure**: Removed legacy `docs/en/` and `docs/es/` references; normalized to `docs/*.en.md` and `docs/*.es.md`.
- **Linting**: Fixed various Markdown linting issues in READMEs (headers, code blocks).

## [3.5.2] - 2025-12-18 (Hotfix)

### Added

- **Net Discovery activity indicator**: Network discovery phases now provide visible activity feedback so the terminal doesn't look "stuck".
- **Timeout-aware ETA**: Progress bars now display a conservative upper bound (`ETA≤ …`) that accounts for configured timeouts.

### Changed

- **Cleaner terminal output**: Progress UI reduces noisy status logs while active to keep the operator experience readable.

### Fixed

- **Post-update flow**: After installing an update, RedAudit now shows a large "restart the terminal" notice, waits for confirmation, and exits to prevent mixed-version execution.

## [3.5.1] - 2025-12-17 (Hotfix)

### Added

- **Output manifest**: When encryption is disabled, RedAudit now writes `run_manifest.json` in the output folder (counts + artifact list).
- **SIEM provenance fields**: `findings.jsonl` / `assets.jsonl` now include `session_id`, `schema_version`, `scanner`, `scanner_version`; `summary.json` adds `redaudit_version`.
- **Silent progress UI**: Rich progress bars now show an ETA for host/vuln phases, and heartbeat "no output" clocking messages no longer spam the terminal.

### Fixed

- **Full `--dry-run` support**: Propagated dry-run across remaining modules so no external commands are executed, while still printing planned commands.
- **Updater UX**: If system install is updated but `~/RedAudit` has local git changes, RedAudit now skips updating the home copy instead of failing the whole update.
- **Post-update hint**: After updating, RedAudit prints a reminder to restart the terminal or run `hash -r` if the banner/version does not refresh.

## [3.5.0] - 2025-12-17 (Reliability & Execution)

### Added

- **Prevent sleep during scans**: Best-effort system/display sleep inhibition while a scan is running (enabled by default; opt-out with `--no-prevent-sleep`).
- **Centralized CommandRunner**: New `redaudit/core/command_runner.py` as a single entry point for external commands (timeouts, retries, secret redaction, incremental `--dry-run` rollout).

### Changed

- **External command execution**: More modules now execute external tools via CommandRunner (scanner/auditor/topology/net discovery), improving safety and making `--dry-run` effective in more places (rollout remains incremental).
- **Documentation**: Updated manuals, usage, troubleshooting, and roadmap to reflect v3.5.0 behavior and flags.

## [3.4.4] - 2025-12-17 (Hotfix)

### Fixed

- **Defaults workflow**: Choosing "Use defaults and continue" now actually applies defaults; starting "immediately" no longer re-asks scan parameters, and can reuse saved targets when available.
- **Docs**: Added a note about restarting the terminal / `hash -r` if the banner version doesn't refresh after updating.

## [3.4.3] - 2025-12-17 (Hotfix)

### Fixed

- **Finding titles**: Web findings now get a short `descriptive_title` derived from parsed observations (improves HTML table titles, webhooks, and playbook headings).
- **Wizard output directory default**: When the wizard would default to `/root/...`, RedAudit now prefers the invoking user’s `Documents` folder (and, when running as root without `sudo`, will use a single detected user under `/home/<user>` when unambiguous).
- **Wizard menu marker**: Replaced the Unicode selector marker with an ASCII marker for consistent rendering across terminals/fonts.

## [3.4.2] - 2025-12-17 (Hotfix)

### Fixed

- **Wizard output directory prompt (sudo)**: If an older persisted default points to `/root/...`, RedAudit automatically rewrites it to the invoking user’s `Documents` directory when running under `sudo`.

## [3.4.1] - 2025-12-17 (Hotfix)

### Fixed

- **Default Output Directory (sudo)**: Reports now default to the invoking user’s Documents folder when running under `sudo` (instead of `/root`).
- **Tilde Expansion (sudo)**: `--output ~/...` and persisted defaults using `~` now expand against the invoking user under `sudo`.
- **Ownership**: Best-effort chown of the report output folder to the invoking user to avoid root-owned artifacts under the user’s home.

## [3.4.0] - 2025-12-17 (Playbook Export)

### Added

- **Remediation Playbooks**: Automatic generation of actionable remediation guides per finding.
  - New module: `redaudit/core/playbook_generator.py`
  - Categories: TLS hardening, HTTP headers, CVE remediation, web hardening, port hardening
  - Output: Markdown files in `<output_dir>/playbooks/` directory
  - Includes: step-by-step instructions, shell commands, and reference links
  - Deduplication: one playbook per category per host

### Changed

- **reporter.py**: Now generates playbooks automatically after scan completion.
- **i18n.py**: Added `playbooks_generated` translation key.

## [3.3.0] - 2025-12-17 (DX Improvements)

### Added

- **Interactive HTML Dashboard** (`--html-report`): Generate standalone HTML reports with Bootstrap + Chart.js.
  - Dark theme with premium aesthetics
  - Severity distribution doughnut chart and Top 10 ports bar chart
  - Sortable tables for hosts and findings
  - Risk score color-coding (green/orange/red)
  - MAC address and vendor columns in host table
  - Self-contained: works offline, no external dependencies at runtime

- **Visual HTML Diff Report** (`--diff`): Compare two scans with side-by-side visual output.
  - New template: `redaudit/templates/diff.html.j2`
  - New function: `format_diff_html()` in `diff.py`
  - Highlights: new hosts (green), removed hosts (red), changed ports (yellow)
  - Badges for severity changes and port deltas

- **Webhook Alerting** (`--webhook URL`): Real-time alerts for high-severity findings.
  - New module: `redaudit/utils/webhook.py`
  - Sends JSON payloads to any webhook endpoint (Slack, Discord, Teams, custom)
  - Filters: only HIGH and CRITICAL severity findings trigger alerts
  - Includes: asset IP, finding title, severity, port, timestamp
  - Timeout: 10 seconds per request with error handling

### Changed

- **reporter.py**: Now generates HTML report automatically when `--html-report` flag is set.
- **reporter.py**: Sends webhook alerts after scan completion when `--webhook URL` is provided.
- **cli.py**: Added `--html-report` and `--webhook URL` flags.
- **pyproject.toml**: Templates directory included in package data.
- **Installer**: Added `python3-jinja2` as dependency for HTML template rendering.

### Fixed

- **HTML Report Error Visibility**: Errors during HTML generation now display in console (not just log file).
- **Bandit CI**: Configured to skip B101 (assert) in tests directory.

## [3.2.3] - 2025-12-16 (HyperScan + Stealth Mode)

### Added

- **HyperScan Module**: New `redaudit/core/hyperscan.py` (~1000 lines) for ultra-fast parallel discovery.
  - Batch TCP scanning with 3000 concurrent connections using asyncio
  - Full UDP sweep across 45+ ports with protocol-specific payloads
  - UDP IoT broadcast probes (WiZ, SSDP, Chromecast, Yeelight, LIFX)
  - Aggressive ARP sweep with 3 retries using arp-scan + arping fallback
  - Backdoor detection with severity levels for suspicious ports (31337, 4444, 6666, etc.)
  - Deep scan mode: full 65535-port scan on suspicious hosts

- **Stealth Mode**: New `--stealth` CLI flag for enterprise networks with IDS/rate limiters.
  - Uses nmap `-T1` paranoid timing template
  - Forces single-threaded sequential scanning
  - Enforces minimum 5 second delay between probes
  - Random jitter already built into rate limiting

- **CLI Logging**: Added visible progress messages for HyperScan results showing ARP/UDP/TCP host counts and duration.

- **Progress Spinners**: Added animated spinners for topology and net_discovery phases showing elapsed time during long-running discovery operations.

### Fixed

- **Net Discovery Auto-Trigger**: Net discovery with HyperScan now automatically runs when topology is enabled (not just in `full` mode). This ensures IoT/WiZ devices are discovered in normal scans with topology.
- **HyperScan Visibility**: Added visible CLI output for HyperScan results showing ARP/IoT/TCP counts and duration.
- **Enhanced IoT Discovery**: Improved smart bulb detection with WiZ registration payload (38899), Yeelight (55443), TP-Link Tapo (20002), and mDNS probes. Increased timeout for slow IoT devices.
- **Network Deduplication**: "Scan ALL" now correctly removes duplicate CIDRs when same network is detected on multiple interfaces (e.g., eth0 + eth1).
- **Defaults Display**: Interactive configuration review now shows 10 fields (was 6) including scan_mode, web_vulns, cve_lookup, txt_report.
- **Config Persistence**: `DEFAULT_CONFIG` expanded to 12 fields for complete settings preservation.

## [3.2.2b] - 2025-12-16 (IoT & Enterprise Discovery)

### Added

- **Enhanced UPNP Discovery**: Increased timeout (10s → 25s), added retry mechanism (2 attempts), SSDP M-SEARCH fallback.
- **Active ARP Scanning**: `netdiscover` now uses active mode by default (`-f` flag), with interface support for multi-homed setups.
- **New `arp_scan_active()`**: Dedicated function using `arp-scan` with retry for more reliable IoT discovery.
- **Dual ARP Discovery**: Uses both `arp-scan` and `netdiscover` with automatic deduplication for maximum coverage.
- **IoT mDNS Service Types**: Added specific queries for `_amzn-wplay` (Alexa), `_googlecast` (Chromecast), `_hap` (HomeKit), `_airplay`.
- **Auto-Pivot `extract_leaked_networks()`**: Returns scannable /24 CIDRs from leaked IPs for automatic hidden network discovery.

### Changed

- **mDNS Timeout**: Increased from 5s to 15s for better IoT device capture.
- **netdiscover Timeout**: Increased from 15s to 20s.
- **Version**: Bumped to 3.2.2b (development/testing).

### Fixed

- **IoT Device Discovery**: Previous scans only found 3 of 10+ devices due to passive ARP mode and short timeouts.
- **hidden_networks JSON sync**: Leaked network IPs now correctly populate `hidden_networks` and `leaked_networks_cidr` in JSON for SIEM/AI pipelines (was only in text report before).

## [3.2.2] - 2025-12-16 (Production Hardening)

### Added

- **Staged Atomic Installation**: Update installation uses `.new` staging directory before atomic rename, with automatic rollback on failure.
- **Post-Install Verification**: Validates key files exist after installation; rolls back both system and home installs if verification fails.
- **CLI Output Tests**: 3 new unit tests verifying status token mapping (OKGREEN→OK, WARNING→WARN).

### Changed

- **CLI Status Labels**: `print_status` now displays user-friendly labels (`[OK]`, `[INFO]`, `[WARN]`) instead of internal tokens (`[OKGREEN]`, `[OKBLUE]`, `[WARNING]`) in all output modes.
- **Updater Documentation**: Renamed from "Secure Update Module" to "Reliable Update Module" with honest documentation about security model.
- **SECURITY.md**: Section 7 renamed to "Reliable Auto-Update" with explicit note about integrity vs. authenticity verification.

### Fixed

- **Visual Token Leakage (B3)**: Internal status tokens no longer appear as literal text in CLI output.
- **Annotated Tag Resolution**: Auto-update now correctly resolves annotated git tags to their underlying commit using `^{}` dereference. Previously, comparison of tag object hash vs. commit hash always failed.

### Security

- **Honest Security Claims**: Documented that the update system verifies commit hashes (integrity) but does NOT perform cryptographic signature verification (authenticity).

### Upgrade Notice

> **⚠️ Users on v3.2.1 or earlier**: The auto-update from v3.2.1 → v3.2.2 may fail due to the annotated tag bug. Please reinstall manually:
>
> ```bash
> curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.2.2/redaudit_install.sh | sudo bash
> ```
>
> After this one-time manual update, future auto-updates will work correctly.

## [3.2.1] - 2025-12-15 (CLI UX)

### Added

- **Defaults control flags**: `--defaults {ask,use,ignore}`, `--use-defaults`, `--ignore-defaults`.
- **Locale language fallback**: CLI detects ES/EN from env/locale when no stored preference exists.
- **Subnet Leak Detection**: Report section identifying hidden networks from HTTP header/redirect leaks (pivoting recon).
- **Installer Support**: Automated installation of `kerbrute` (GitHub binary) and `proxychains4`.
- **UI Polish**: Added colored separator lines and spacing to interactive wizard prompts.

### Fixed

- **Update prompt output**: Terminal-friendly summary (date/type/highlights), filters Markdown noise, and keeps language consistent with a clear fallback note.
- **Defaults wizard UX**: Removed redundant confirmations when the user answers "no" to saving defaults; added an explicit startup choice when persisted defaults exist (use/review/ignore).

## [3.2.0] - 2025-12-15 (Enhanced Net Discovery)

### Added

- **Enhanced Net Discovery (v3.2)**: New `net_discovery` report block with DHCP/NetBIOS/mDNS/UPNP/ARP/fping discovery and VLAN candidate analysis (`--net-discovery`).
- **Red Team Recon (guarded)**: Opt-in recon under `--redteam` with best-effort SNMP/SMB/RPC/LDAP/Kerberos/DNS + passive L2 signals in `net_discovery.redteam`.
- **New tuning flags**: `--net-discovery-interface`, `--redteam-max-targets`, `--snmp-community`, `--dns-zone`, `--kerberos-realm`, `--kerberos-userlist`, `--redteam-active-l2`.

### Changed

- **Version**: Updated to 3.2.0.

## [3.1.4] - 2025-12-15 (Output Quality)

### Added

- **Descriptive Finding Titles**: Generate human-readable titles based on finding type (e.g., "Missing X-Frame-Options Header" instead of "Finding on URL")
- **OS Fingerprint Extraction**: New `extract_os_detection()` function captures OS info from Nmap output
- **Nikto Cross-Validation**: `detect_nikto_false_positives()` compares Nikto findings with curl/wget headers to identify contradictions
- **RFC-1918 Severity Adjustment**: `is_rfc1918_address()` reduces severity for internal IP disclosure findings on private networks
- **Schema Version Constant**: New `SCHEMA_VERSION` constant separate from app `VERSION` for report schema versioning

### Changed

- **TestSSL Timeout**: Increased default from 60s to 90s, now configurable via `timeout` parameter
- **PCAP Paths**: Reports now use relative paths (`pcap_file`) for portability, with `pcap_file_abs` for internal use
- **siem.py**: `enrich_vulnerability_severity()` adds `severity_note` and `potential_false_positives` fields when applicable

## [3.1.3] - 2025-12-15 (Async UDP & Topology)

### Added

- **Async UDP probe (best-effort)**: Fast concurrent probing of priority UDP ports during deep scan, recorded as `deep_scan.udp_priority_probe`.
- **Async topology discovery**: Parallelized command collection for faster ARP/VLAN/LLDP + gateway mapping (best-effort).

### Changed

- **README Structure**: Added `udp_probe.py` module to project structure
- **README Features**: Added Async UDP Priority Probe and Async Topology Discovery to Features section
- **README Topology**: Updated topology.py description to reflect async implementation
- **ROADMAP Update**: Added v3.1.2/v3.1.3 milestones, marked v3.1.3 as CURRENT
- **DIDACTIC_GUIDE**: Updated version references from v3.1.1 to v3.1.3

## [3.1.2] - 2025-12-14 (Update UX)

### Fixed

- **Updater notes preview**: Terminal-friendly rendering (strip Markdown noise, wrap long lines).
- **Updater restart**: PATH-aware restart attempts and clear fallback instructions when restart fails.

### Changed

- **Interactive prompts**: Added FULL UDP presets, clarified topology-only mode, and added confirmation/explanations when saving defaults.

## [3.1.1] - 2025-12-14 (Topology, Defaults & UDP Coverage)

### Added

- **Topology Discovery (best-effort)**: Optional ARP/VLAN/LLDP + gateway/routes mapping (`--topology`, `--topology-only`)
- **Persistent Defaults**: Save common settings to `~/.redaudit/config.json` via `--save-defaults` (used as defaults in future runs)
- **Configurable UDP Coverage**: `--udp-ports N` (50-500) to tune full UDP identity scan coverage

### Changed

- **Deep Scan UDP Phase 2b**: Uses configurable `--top-ports N` and records `udp_top_ports` in deep scan output
- **Report Schema**: Added optional `topology` block in the root report (when enabled)

## [3.1.0] - 2025-12-14 (SIEM & AI Pipeline)

### Added

- **JSONL Export Views**: Auto-generated flat files for SIEM/AI ingestion (when report encryption is disabled)
  - `findings.jsonl` - One finding per line
  - `assets.jsonl` - One asset per line
  - `summary.json` - Compact dashboard summary
  - New module: `redaudit/core/jsonl_exporter.py`

- **Finding Deduplication**: Deterministic `finding_id` hashes
  - SHA256 of asset + scanner + port + signature + title
  - Enables cross-scan correlation and tracking

- **Category Classification**: Automatic finding categorization
  - Categories: surface, misconfig, crypto, auth, info-leak, vuln
  - New function: `classify_finding_category()` in `siem.py`

- **Severity Normalization**: CVSS-like scoring
  - `normalized_severity`: 0.0-10.0 scale
  - `original_severity`: Preserved tool-native values
  - Enum: `info`, `low`, `medium`, `high`, `critical`

- **Parsed Observations**: Structured evidence extraction
  - New module: `redaudit/core/evidence_parser.py`
  - Extracts meaningful findings from Nikto/TestSSL raw output
  - Large outputs externalized to `evidence/` folder (only when report encryption is disabled)

- **Scanner Versions**: Tool provenance tracking
  - New module: `redaudit/core/scanner_versions.py`
  - Detects: nmap, nikto, testssl, whatweb, searchsploit
  - Added to report as `scanner_versions` object

### Changed

- **Schema Version**: Updated from 2.0 to 3.1
- **Report Metadata**: Added `generated_at` timestamp
- **Version**: Updated to 3.1.0

---

## [3.0.4] - 2025-12-14 (Interactive UX)

### Changed

- **Host limit prompt**: Interactive default is now "all" (`todos`/`all`) and the question clarifies that numbers set a maximum host count (not a host selector).
- **Documentation**: Clarified `--max-hosts` semantics and updated manuals.
- **Version**: Updated to 3.0.4

---

## [3.0.3] - 2025-12-14 (Update UX)

### Added

- **More explicit auto-update output**: Shows target ref/commit, file changes (+/~/-), and explicit install/backup steps.

### Fixed

- **Language preservation on update**: Auto-update no longer resets the installed language (e.g., Spanish stays Spanish).

### Changed

- **Version**: Updated to 3.0.3

---

## [3.0.2] - 2025-12-14 (UX, Reporting & NVD)

### Added

- **PCAP visibility**: Final summary includes a PCAP count; TXT reports include PCAP path when captured.
- **TXT reporting clarity**: Deep scan sections include command counts (identity-only vs executed deep scan).
- **CVE reporting (TXT)**: When CVE enrichment is present, TXT reports include CVE summaries and per-port CVE counts.

### Changed

- **Version**: Updated to 3.0.2
- **CLI output**: Thread-safe status printing + word-wrapping avoids split words and interleaved output in concurrent scans.
- **Spanish UX**: Completed missing translations for scan status/progress and deep scan messaging.
- **NVD enrichment**: Skips overly broad wildcard-version CPE queries when service version is unknown.

### Fixed

- **NVD messaging**: Correct API key source messaging (no longer reports CLI when key came from config/env).

---

## [3.0.1] - 2025-12-13 (Configuration & UX)

### Added

- **NVD API Key Configuration**: Persistent storage for CVE correlation
  - New module: `redaudit/utils/config.py`
  - Config file: `~/.redaudit/config.json` (0600 permissions)
  - Environment variable support: `NVD_API_KEY`
  - Interactive setup prompt in auditor with 3 storage options
  - Installer prompts for API key during `redaudit_install.sh`
  - EN/ES translations for all new prompts

- **CVE Correlation Interactive Prompt**: New question in interactive setup
  - "Enable CVE correlation via NVD?" (default: no)
  - If yes and no key configured, triggers API key setup flow

### Changed

- **Version**: Updated to 3.0.1
- **Auto-update hardening**: Updates now resolve the published tag and verify the commit hash before installation.
- **Installer hardening**: `testssl.sh` installation is pinned to a known tag/commit and verified.
- **CVE lookup resilience**: NVD queries retry on transient errors (429/5xx/network) with backoff.
- **Privileges UX**: Added `--allow-non-root` to run in limited mode without sudo/root.

---

## [3.0.0] - 2025-12-12 (Major Feature Release)

### Added

- **IPv6 Support**: Full scanning capabilities for IPv6 networks
  - `is_ipv6()`, `is_ipv6_network()` helper functions in `scanner.py`
  - `get_nmap_arguments_for_target()` automatically adds `-6` flag for IPv6 targets
  - IPv6 network detection in `network.py` (netifaces + fallback)
  - CLI flag: `--ipv6` for IPv6-only scanning mode

- **Magic Byte Validation**: Enhanced false positive detection
  - `verify_magic_bytes()` in `verify_vuln.py`
  - Downloads first 512 bytes and verifies file signatures
  - Supports: tar, gzip, zip, pem file formats
  - Integrated as third verification layer in Smart-Check

- **CVE Correlation (NVD)**: Deep vulnerability intelligence
  - New module: `redaudit/core/nvd.py`
  - NIST NVD API 2.0 integration
  - CPE 2.3 matching for accurate CVE lookup
  - 7-day cache for offline use and rate limit compliance
  - CLI flags: `--nvd-key`, `--cve-lookup`

- **Differential Analysis**: Compare scan reports
  - New module: `redaudit/core/diff.py`
  - Identifies new hosts, removed hosts, port changes
  - Generates both JSON and Markdown output
  - CLI flag: `--diff OLD NEW`

- **Proxy Chains (SOCKS5)**: Network pivoting support
  - New module: `redaudit/core/proxy.py`
  - `ProxyManager` class for session management
  - Proxychains wrapper integration
  - CLI flag: `--proxy URL`

- **Enhanced Auto-Update**: Reliable update system
  - Git clone approach (replaces git pull)
  - Runs install script with user's language preference
  - Copies to `~/RedAudit` with all documentation
  - Installation verification and ownership fix

### Changed

- **Version**: Major version bump to 3.0.0
- **Auditor**: Added `proxy_manager` and v3.0 config options

---

## [2.9.0] - 2025-12-12 (Smart Improvements)

### Added

- **Smart-Check Module**: Nikto false positive filtering
  - New module: `redaudit/core/verify_vuln.py`
  - Content-Type verification to detect Soft 404s
  - Size validation for suspiciously small files
  - Automatic filtering with count tracking

- **Entity Resolution Module**: Multi-interface host consolidation
  - New module: `redaudit/core/entity_resolver.py`
  - Groups hosts by identity fingerprint (hostname/NetBIOS/mDNS)
  - New JSON field: `unified_assets` array
  - Asset type guessing (router, workstation, mobile, iot, etc.)

- **SIEM Professional Enhancement**: Enterprise SIEM integration
  - New module: `redaudit/core/siem.py`
  - ECS v8.11-aligned fields for Elastic integration
  - Severity scoring (critical/high/medium/low/info)
  - Risk scores (0-100) per host
  - Auto-generated tags for categorization
  - Observable hash (SHA256) for deduplication
  - CEF format for ArcSight/McAfee

- **New Tests**: 46 unit tests for new modules

### Changed

- **UDP Taming**: Optimized UDP scanning for 50-80% faster scans
  - Uses `--top-ports 100` instead of full port scan
  - Strict `--host-timeout 300s` per host
  - `--max-retries 1` for LAN efficiency

- **Version**: Updated to 2.9.0

---

## [2.8.1] - 2025-12-11 (UX Improvements)

### Added

- **Vulnerability Scan Progress Bar**: Rich progress bar for vulnerability scanning phase
  - Shows spinner, percentage, completed/total hosts, and elapsed time
  - Displays current host being scanned
  - Graceful fallback if rich library unavailable

- **Module Indicators**: Visual feedback showing active tool during vulnerability scans
  - `[testssl]` prefix for SSL/TLS deep analysis
  - `[whatweb]` prefix for web technology detection
  - `[nikto]` prefix for web vulnerability scanning
  - Updates `current_phase` for activity monitoring

### Changed

- **PCAP File Organization**: PCAP files now saved inside timestamped result folder
  - Folder created BEFORE scanning starts (`_actual_output_dir`)
  - All output files (reports + PCAPs) consolidated in single directory
  - Fixes issue where PCAPs were saved to parent directory

- **PCAP Size Optimization**: Reduced capture from unlimited to 200 packets
  - PCAP files now ~50-150KB instead of several MB
  - Sufficient for protocol analysis without excessive storage
  - tcpdump auto-stops after 200 packets captured

- **Default Output Directory**: Changed from `~/RedAuditReports` to `~/Documents/RedAuditReports`
  - Reports now saved in user's Documents folder by default
  - More intuitive location for users

- **Version**: Updated to 2.8.1

### Improved

- **Auto-Update System**: Enhanced from detection-only to full installation
  - Now performs `git reset --hard` to prevent conflicts
  - Automatically copies updated files to `/usr/local/lib/redaudit/`
  - Auto-restarts with `os.execv()` after successful update (no manual restart needed)
  - Eliminates the need for manual `git pull` and reinstall

### Fixed

- **Ctrl+C During Setup**: Fixed hang when pressing Ctrl+C before scan starts
  - Added `KeyboardInterrupt` handling in all input methods (`ask_yes_no`, `ask_number`, `ask_choice`, `ask_manual_network`)
  - Now exits immediately if interrupted during configuration phase
  - Only attempts graceful shutdown when scan is actually running

---

## [2.8.0] - 2025-12-11 (Completeness & Reliability)

### Added

- **Host Status Accuracy (Phase 1)**: Introduced intelligent status finalization
  - New status types: `up`, `down`, `filtered`, `no-response`
  - `finalize_host_status()` evaluates deep scan results to determine accurate status
  - Hosts with MAC/vendor detected but no initial response now show as `filtered` instead of `down`

- **Intelligent UDP Scanning (Phase 2)**: 3-phase adaptive deep scan strategy
  - Phase 2a: Quick scan of 17 priority UDP ports (DNS, DHCP, SNMP, NetBIOS, etc.)
  - Phase 2b: Full UDP scan only in `full` mode and if no identity found
  - New config: `udp_mode` (default: `quick`)
  - New constant: `UDP_PRIORITY_PORTS` with most common UDP services

- **Concurrent PCAP Capture (Phase 3)**: Traffic capture synchronized with scanning
  - `start_background_capture()` - Starts tcpdump before scanning begins
  - `stop_background_capture()` - Collects results after scanning completes
  - Captures actual scan traffic instead of empty post-scan windows

- **Banner Grab Fallback (Phase 4)**: Enhanced service identification
  - `banner_grab_fallback()` - Uses nmap `--script banner,ssl-cert` for unidentified ports
  - Automatically runs on ports with `tcpwrapped` or `unknown` service
  - Merges results into port records with `banner` and `ssl_cert` fields

- **Secure Auto-Update System (Phase 5)**: GitHub-integrated update checking
  - New module: `redaudit/core/updater.py`
  - Checks GitHub API for latest releases at startup (interactive prompt)
  - Shows release notes/changelog for new versions
  - Secure git-based updates with integrity verification
  - CLI flag: `--skip-update-check` to disable
  - Translations for update messages in English and Spanish

- **Timestamped Report Folders (Phase 6)**: Organized report structure
  - Reports now saved in subfolders: `RedAudit_YYYY-MM-DD_HH-MM-SS/`
  - Each scan session gets its own directory
  - PCAP files and reports organized together

### Changed

- **Deep Scan Strategy**: Updated from `adaptive_v2.5` to `adaptive_v2.8`
  - Concurrent traffic capture during entire scan duration
  - Three-phase UDP strategy for faster typical scans
  - Improved messaging with phase-specific timing estimates

- **Constants**: Added new constants for v2.8.0 features
  - `STATUS_UP`, `STATUS_DOWN`, `STATUS_FILTERED`, `STATUS_NO_RESPONSE`
  - `UDP_PRIORITY_PORTS`, `UDP_SCAN_MODE_QUICK`, `UDP_SCAN_MODE_FULL`
  - `DEEP_SCAN_TIMEOUT_EXTENDED`, `UDP_QUICK_TIMEOUT`

- **CLI**: New flags `--udp-mode` and `--skip-update-check`

- **Version**: Updated to 2.8.0

### Technical

- New module `redaudit/core/updater.py` with:
  - `parse_version()`, `compare_versions()`
  - `fetch_latest_version()`, `check_for_updates()`
  - `perform_git_update()`, `interactive_update_check()`

- New functions in `scanner.py`:
  - `start_background_capture()` / `stop_background_capture()`
  - `banner_grab_fallback()`
  - `finalize_host_status()`

- Improved `scan_host_ports()`:
  - Tracks unknown ports for banner fallback
  - Finalizes status after all enrichment

- Updated `reporter.py`:
  - Creates timestamped subfolders for reports

---

## [2.7.0] - 2025-12-09 (Speed & Integration)

### Added

- **Pre-scan Asyncio Engine (A1)**: Fast port discovery using asyncio TCP connect
  - New module: `redaudit/core/prescan.py`
  - CLI flags: `--prescan`, `--prescan-ports`, `--prescan-timeout`
  - Up to 500 concurrent port checks with configurable batching
  - Port range parsing: `1-1024`, `22,80,443`, or combined `1-100,443,8080-8090`

- **SIEM-Compatible Output (A5)**: Enhanced JSON reports for Elastic and other SIEMs
  - New fields: `schema_version`, `event_type`, `session_id`, `timestamp_end`
  - Scanner metadata: name, version, mode
  - Targets array for multi-network scans

- **Bandit Security Linting (A4)**: Static security analysis in CI pipeline
  - Added Bandit to GitHub Actions workflow
  - Scans for common security issues (B-series checks)

### Changed

- **Jitter Rate-Limiting (A3)**: Added ±30% random variance to delay for IDS evasion
- **Version**: Updated to 2.7.0

---

## [2.6.2] - 2025-12-09 (Signal Handling Hotfix)

### Fixed

- **Signal Handler Subprocess Cleanup (C1)**: SIGINT (Ctrl+C) now properly terminates all active subprocesses (nmap, tcpdump, etc.) instead of leaving orphan processes
  - Added `register_subprocess()`, `unregister_subprocess()`, `kill_all_subprocesses()` methods
  - Child processes receive SIGTERM first, then SIGKILL if still alive after 2 seconds
  - Thread-safe implementation with lock protection

- **Futures Cancellation (C2)**: Pending ThreadPoolExecutor futures are now cancelled when interrupted
  - Prevents unnecessary work when user aborts scan
  - Applied to both rich progress bar and fallback progress modes

### Changed

- **Version**: Updated to 2.6.2

---

## [2.6.1] - 2025-12-08 (Exploit Intelligence & SSL/TLS Deep Analysis)

### Added

- **SearchSploit Integration**: Automatic exploit lookup from ExploitDB for services with detected versions
  - Queries `searchsploit` for known exploits when product+version identified
  - Results displayed in both JSON and TXT reports
  - Timeout: 10 seconds per query
  - Runs in all scan modes (fast/normal/full)
  - New function: `exploit_lookup()` in `redaudit/core/scanner.py`

- **TestSSL.sh Integration**: Comprehensive SSL/TLS security analysis for HTTPS services
  - Deep SSL/TLS vulnerability scanning (Heartbleed, POODLE, BEAST, etc.)
  - Weak cipher and protocol detection
  - Only runs in `full` mode (60-second timeout per port)
  - Results include summary, vulnerabilities, weak ciphers, and protocols
  - New function: `ssl_deep_analysis()` in `redaudit/core/scanner.py`

- **Enhanced Reporting**:
  - TXT reports now show known exploits for each service
  - TXT reports display TestSSL vulnerability findings
  - JSON reports automatically include all new data fields

- **Internationalization**: Added English and Spanish translations for new features:
  - `exploits_found` - Exploit discovery notifications
  - `testssl_analysis` - SSL/TLS analysis progress messages

### Changed

- **Installation**: Updated `redaudit_install.sh` to install `exploitdb` and `testssl.sh` packages
- **Verification**: Updated `redaudit_verify.sh` to check for new tools
- **Dependencies**: Added searchsploit and testssl.sh to optional tools list (12 total optional tools)
- **Version**: Updated to 2.6.1

### Philosophy

Both tools maintain RedAudit's adaptive approach:

- **SearchSploit**: Lightweight, runs automatically when version info available
- **TestSSL**: Heavy analysis, only in full mode for actionable security findings

---

## [2.6.0] - 2025-12-08 (Modular Architecture)

### Added

- **Modular Package Structure**: Refactored monolithic `redaudit.py` (1857 lines) into organized package:
  - `redaudit/core/auditor.py` - Main orchestrator class
  - `redaudit/core/crypto.py` - Encryption/decryption utilities
  - `redaudit/core/network.py` - Network detection
  - `redaudit/core/reporter.py` - Report generation
  - `redaudit/core/scanner.py` - Scanning logic
  - `redaudit/utils/constants.py` - Named configuration constants
  - `redaudit/utils/i18n.py` - Internationalization
- **CI/CD Pipeline**: GitHub Actions workflow (`.github/workflows/tests.yml`)
  - Automated testing on Python 3.9, 3.10, 3.11, 3.12
  - Codecov integration for coverage reporting
  - Flake8 linting

- **New Test Suites**:
  - `tests/test_network.py` - Network detection tests with mocking
  - `tests/test_reporter.py` - Report generation and file permission tests
- **Package Entry Point**: `python -m redaudit` support

### Changed

- **Named Constants**: All magic numbers replaced with descriptive constants
- **Test Coverage**: Expanded from ~25 to 34 automated tests
- **Version**: Updated to 2.6.0

### Fixed

- **Python 3.9 Compatibility**: Fixed `str | None` union syntax in `test_sanitization.py` to use `Optional[str]`
- **Test Imports**: Updated `test_encryption.py` to use module-level functions (`derive_key_from_password`, `encrypt_data`) instead of non-existent instance methods
- **Flake8 Compliance**: All lint errors resolved:
  - Removed trailing whitespace from blank lines (W293)
  - Removed 12 unused imports across `auditor.py`, `scanner.py`, `reporter.py` (F401)
  - Added whitespace around arithmetic operators (E226)
  - Renamed ambiguous variable `l` to `line` (E741)

### Backward Compatibility

- Original `redaudit.py` preserved as thin wrapper for backward compatibility
- All existing scripts and workflows continue to work unchanged

---

## [2.5.0] - 2025-12-07 (Security Hardening)

### Added

- **File Permission Security**: Reports now use secure permissions (0o600 - owner read/write only)
- **Integration Tests**: Comprehensive test suite (`test_integration.py`)
- **Encryption Tests**: Full test coverage for encryption functionality (`test_encryption.py`)

### Changed

- **Sanitizers Hardened**: `sanitize_ip()` and `sanitize_hostname()` now:
  - Validate input type (only `str` accepted)
  - Strip whitespace automatically
  - Return `None` for invalid types (int, list, etc.)
  - Enforce maximum length limits
- **Cryptography Handling**: Improved graceful degradation
  - `check_dependencies()` now verifies cryptography availability
  - `setup_encryption()` supports non-interactive mode with `--encrypt-password` flag
  - `setup_encryption()` doesn't prompt for password if cryptography unavailable
  - Random password generation for non-interactive mode when password not provided
  - Clear warning messages in both English and Spanish
- **Version**: Updated to 2.5.0

### Security

- **Input Validation**: All user inputs now validated for type and length
- **File Permissions**: All generated reports use secure permissions (0o600)
- **Error Handling**: Better exception handling prevents information leakage

---

## [2.4.0] - 2025-12-07 (Adaptive Deep Scan)

### Added

- **Adaptive Deep Scan (v2.5)**: Implemented a smart 2-phase strategy (Aggressive TCP first -> UDP+OS fallback). to maximize speed and data.
- **Vendor/MAC Detection**: Native regex parsing to extract hardware vendor from Nmap output.
- **Installer**: Refactored `redaudit_install.sh` to specific clean copy operations without embedded Python code.

### Changed

- **Heartbeat**: Professional messaging ("Nmap is still running") to reduce user anxiety during long scans.
- **Reporting**: Added `vendor` and `mac_address` fields to JSON/TXT reports.
- **Version**: Updated to 2.4.0

---

## [2.3.1] - 2024-05-20 (Security Hardening)

### Added

- **Security Hardening**: Implemented strict sanitization for all user inputs (IP addresses, hostnames, interfaces) to prevent command injection.
- **Report Encryption**: Added optional AES-128 encryption (Fernet) for generated reports. Included a helper script (`redaudit_decrypt.py`) for decryption.
- **Rate Limiting**: Added configurable delay between concurrent host scans for stealthier operations.
- **Professional Logging**: Implemented a rotating file logger (`~/.redaudit/logs/`) for detailed audit trails and debugging.
- **Port Truncation**: Automatic truncation of port lists if >50 ports are found on a single host, reducing report noise.

### Changed

- **Dependencies**: Added `python3-cryptography` as a core dependency for the encryption feature.
- **Configuration**: Updated interactive setup to include prompts for encryption and rate limiting.

## [2.3.0] - 2024-05-18

### Added

- **Heartbeat Monitor**: Background thread that prints activity status every 60s and warns if Nmap hangs (>300s).
- **Graceful Exit**: Handles Ctrl+C (SIGINT) to save partial results before exiting.
- **Deep Scan**: Automatically triggers aggressive Nmap scan + UDP if a host shows few open ports.
- **Traffic Capture**: Captures small PCAP snippets (50 packets) for active hosts using `tcpdump`.
- **Enrichment**:
  - **WhatWeb**: fingerprinting for web services.
  - **Nikto**: scan for web vulnerabilities (only in FULL mode).
  - **DNS/Whois**: reverse lookup and basic whois for public IPs.
  - **Curl/Wget/OpenSSL**: HTTP headers and TLS certificate info.

### Changed

- **Dependency Management**: Stopped using `pip`. All dependencies are now installed via `apt` (python3-nmap, etc.) to match Kali/Debian standards.
- **Networking**: Replaced `netifaces` (often missing) with a robust parsing of `ip addr show` or `ifconfig`.
- **Architecture**: `redaudit_install.sh` now embeds the Python core directly, removing the need for a separate `.py` file download.

### Fixed

- **Tracebacks**: Added extensive `try/except` blocks to prevent crashes during scanning errors.
- **Permissions**: Added check for `root` (sudo) at startup.
