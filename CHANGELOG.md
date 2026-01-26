# Changelog

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ES/CHANGELOG_ES.md)

All notable changes are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes live under `docs/releases/` for additional context.

## [Unreleased]

### Fixed

- None.

## [4.19.0] - 2026-01-26

### Added

- **Nuclei Runtime Budget + Resume**: Optional time budget creates `nuclei_resume.json` and `nuclei_pending.txt`, with a 15-second resume prompt.
- **Resume Entry Points**: Main menu "Resume Nuclei (pending)" and CLI flags `--nuclei-resume` / `--nuclei-resume-latest`.

### Improved

- **Report Snapshot**: Config snapshot and schema now include `nuclei_max_runtime`, plus resume metadata in the Nuclei summary.

## [4.18.22] - 2026-01-25

### Fixed

- **Nuclei Timeout Floor**: Split retries keep the configured batch timeout as a floor to avoid coverage loss on slow targets.

## [4.18.21] - 2026-01-25

### Improved

- **Updater Home Refresh**: System updates now back up a dirty `~/RedAudit` folder and refresh the home copy so documentation stays current.

## [4.18.20] - 2026-01-25

### Improved

- **ANSI Status Contrast**: Status lines now apply the status color to full message text for consistent contrast outside Rich.

### Fixed

- **UI Language Sync**: UI manager now re-syncs when CLI language changes to prevent mixed EN/ES output.
- **Nuclei Parallel Clamp**: Long Nuclei timeouts now reduce parallel batches to avoid full-scan timeouts.

## [4.18.19] - 2026-01-25

### Improved

- **UI Progress Styling**: Rich progress output now applies the status color to all message lines for consistent contrast.
- **Config Snapshot Coverage**: Report snapshots now include `deep_id_scan`, `trust_hyperscan`, and `nuclei_timeout`.

### Fixed

- **UI Language Sync**: Language changes now update the UI manager to prevent mixed EN/ES output.
- **Progress Signal Filtering**: WARN signal detection recognizes Spanish keywords during progress rendering.
- **i18n Status Messages**: Dependency, auth-failure, and scan-error messages now use localized strings.

## [4.18.18] - 2026-01-24

### Added

- **Low-Impact HTTP Probe**: Phase 0 enrichment now supports a short HTTP/HTTPS probe for vendor-only hosts with zero open ports when enabled.

### Improved

- **Wizard Contrast**: Non-selected menu options render in blue and default values are highlighted in prompts for readability.
- **Nuclei Split Timeouts**: Batch split retries now clamp timeouts to avoid long stalls on slow targets.

### Fixed

- **Phase0 Summary Accounting**: Smart scan summaries now respect `low_impact_enrichment` when the config is a `ConfigurationContext`.

## [4.18.17] - 2026-01-24

### Added

- **Net Discovery UDP Count**: Pipeline summaries now include total HyperScan UDP port counts for clarity in reports.

### Fixed

- **HyperScan-First Summary Alignment**: HyperScan-First comparisons now track TCP-only discovery to match CLI output.

## [4.18.16] - 2026-01-24

### Added

- **Coverage Guardrail**: The engineering workflow now requires 100% test coverage for modified code paths.

### Improved

- **Test Coverage**: Expanded automated tests to raise overall coverage to 98% and exercise updater flows.

## [4.18.15] - 2026-01-24

### Improved

- **Hostname Hint Store**: Hostname-based device hints now load from the signature data file for configurable identity and asset classification.

## [4.18.14] - 2026-01-24

### Added

- **Signature Data Store**: Vendor hinting and Nuclei FP templates now load from data files for easier updates.

### Fixed

- **Auditor IP Exclusion Fallback**: Adds best-effort local IP fallback when network info and topology are unavailable.

## [4.18.13] - 2026-01-24

### Added

- **Auditor Exclusions**: Run manifests now include excluded auditor IPs and reasons for transparency in automated reviews.

### Fixed

- **SMB Domain Parsing**: SMB agentless parsing no longer falls through to FQDN lines when the domain field is blank.

## [4.18.12] - 2026-01-23

### Fixed

- **HyperScan-First Metrics**: The HyperScan-First sweep now drives `hyperscan_vs_final` comparisons to avoid undercounting from quick discovery ports.
- **HyperScan-First Masscan Merge**: RustScan-driven discovery now merges any masscan fallback ports instead of replacing full results.
- **DHCP Hint Accuracy**: DHCP timeout hints no longer claim missing IPv4 when the default route already provides a source address.
- **HTML Auth Errors (ES)**: Spanish HTML reports now translate authenticated scan error messages.
- **Auditor IP Exclusion**: Filters now exclude local interface and route source IPs to avoid listing the scanner node as a target.

## [4.18.11] - 2026-01-23

### Fixed

- **DHCP Hint Accuracy**: Avoids reporting missing IPv4 hints when interface data cannot be verified.
- **HTML Pipeline Errors (ES)**: Pipeline error messages are now translated in Spanish reports.
- **HTML Auth Summary**: Authenticated scan outcomes are now visible in HTML reports.
- **Updater Repo Sync**: After updates, the updater refreshes tags and fast-forwards clean `main` checkouts to avoid stale version prompts.
- **Lab Log Growth**: The lab setup script now applies Docker log rotation to prevent runaway container logs.
- **Lab SMB Deploy**: The `.30` SMB container is force-redeployed to avoid stale configuration.

### Documentation

- **Lab Cleanup & Manual Log Rotation**: Documented clean lab removal and the log rotation flags for manual runs (EN/ES).

## [4.18.10] - 2026-01-23

### Fixed

- **DHCP Timeout Hints**: Added best-effort hints for DHCP broadcast timeouts to help interpret missing responses.
- **SSH Auth Port Detection**: Authenticated scans now recognize SSH on non-22 ports (e.g., 2222).

## [4.18.9] - 2026-01-23

### Improved

- **Nuclei Traceability**: Report summaries now include Nuclei profile and full-coverage metadata in HTML outputs.
- **Topology Noise Reduction**: ARP discovery deduplicates identical IP/MAC entries to reduce report clutter.

### Fixed

- **Hidden Network Filtering**: In-scope targets are now filtered consistently to avoid false network leak flags.

## [4.18.8] - 2026-01-22

### Improved

- **Installer Toolchain Pinning**: Added `REDAUDIT_TOOLCHAIN_MODE=latest` for testssl/kerbrute plus explicit version overrides (`TESTSSL_VERSION`, `KERBRUTE_VERSION`, `RUSTSCAN_VERSION`).
- **Poetry Lockfile**: Added `poetry.lock` for evaluation alongside pip-tools.
- **Red Team Refactor**: Split Red Team discovery into a dedicated module to reduce `net_discovery.py` size.

### Fixed

- **Kerbrute Installer Message**: Avoids reporting "already installed" after a fresh install.

### Documentation

- **Installer Toolchain Policy**: Documented toolchain mode and version overrides in README and manuals.

## [4.18.7] - 2026-01-22

### Fixed

- **CLI PCAP Count**: Final summary now uses per-run PCAP metadata to avoid counting captures from other runs.

## [4.18.6] - 2026-01-22

### Fixed

- **Auth Scan Lynis Output**: Host objects now store Lynis results safely to avoid `TypeError` crashes.
- **Agentless Filter Init**: Removed duplicate `host_agentless` assignment in the Nuclei false-positive filter path.
- **PCAP Summary Count**: CLI summary now counts all PCAP artifacts, including full capture files.
- **Identity Threshold Validation**: `--identity-threshold` is now bounded to 0-100 with a safe fallback.
- **Docs Consistency**: Clarified thread fallback, jitter detail, identity threshold range, and USAGE section numbering.

## [4.18.5] - 2026-01-22

### Fixed

- **Deep Scan Output Truncation**: Deep scan now captures full stdout to avoid missing ports in high-verbosity Nmap runs.
- **HyperScan FD Safety**: HyperScan TCP batch size now caps to 80% of the system FD soft limit to prevent `Too many open files`.

## [4.18.4] - 2026-01-21

### Fixed

- **Report Traceability**: Nuclei suspected items are now listed in HTML/TXT for manual review.
- **Discovery Errors Visibility**: Net Discovery errors are now surfaced in HTML/TXT pipeline sections.
- **Config Snapshot Completeness**: Nuclei profile and full coverage options are now saved in snapshots/summary.
- **DHCP Discovery Clarity**: DHCP discovery now defaults to the default-route interface, probes all IPv4 interfaces in full mode, and reports timeouts as no-response.

## [4.18.3] - 2026-01-21

### Fixed

- **HyperScan Progress Output**: Suppressed per-host status lines during Rich progress to avoid mixed UI.
- **Nuclei Wizard Clarity**: Profile labels now describe template scope; full coverage prompt clarifies port coverage.

## [4.18.2] - 2026-01-21

### Fixed

- **UI Color Consistency**: Status colors now render correctly during HyperScan progress output.
- **Nuclei Full Coverage Defaults**: Full coverage defaults to YES only when the Nuclei profile is Full.
- **Pipeline Sources**: Summary source counts now match consolidated findings.
- **Run Manifest PCAP Count**: PCAP counts now reflect all listed artifacts.

## [4.18.1] - 2026-01-20

### Fixed

- **Nuclei Report Consistency**: HTML/TXT now surface partial status, timeouts/failed batches, and suspected-only results.
- **Vulnerability Source Summary**: Pipeline source counts now reflect enriched findings instead of falling back to `unknown`.
- **Full Coverage vs Auto-Fast**: Auto-fast profile switching is skipped when full coverage is enabled to honor the selected profile.

## [4.18.0] - 2026-01-20

### Fixed

- **Rich Progress Color Bugs**: Fixed [WARN], [OK], and [INFO] messages appearing white during progress bar display.
  - Root cause: New Console() was bypassing active Rich progress, losing color.
  - Fix: Added `_active_progress_console` tracking in UIManager.
  - Fixed Deep Scan and Net Discovery heartbeats to use `Text()` objects.

### Improved

- **Shortened Wizard Prompts**: Reduced truncation in terminal by shortening prompts:
  - `nuclei_full_coverage_q`: Shortened to avoid terminal wrap.
  - `trust_hyperscan_q`: Simplified for clarity.

### Documentation

- **Nuclei Configuration Section**: Added comprehensive Nuclei section to USAGE.en.md and USAGE.es.md explaining:
  - Scan profiles (fast/balanced/full) with timing estimates.
  - Full coverage option (wizard-only, not CLI flag).
  - RustScan as optional performance boost.
- **CLI Reference Updates**: Added missing `--profile` and `--nuclei-timeout` flags to MANUAL CLI reference.
- **Corrected**: `--nuclei-full` does NOT exist as a CLI flag (wizard-only option).

## [4.17.0] - 2026-01-20

### Added

- **Nuclei Full Coverage Option**: New wizard question to scan ALL HTTP ports with Nuclei.
  - Exhaustivo mode: defaults to YES (full coverage for pentesting-like scans).
  - Custom mode: defaults to NO (audit-focus efficiency).
  - Config key: `nuclei_full_coverage` skips target limiting when true.

### Tests

- Added `TestNucleiFullCoverage` (4 tests) and `TestNucleiFullCoverageI18n` (2 tests).

## [4.16.0] - 2026-01-19

### Added

- **Nuclei Audit-Focus Mode**: Multi-port hosts (3+ HTTP ports) now limited to 2 URLs for Nuclei scanning.
  - Prioritizes standard ports (80, 443, 8080, 8443) for audit efficiency.
  - Reduces scan time significantly (estimated 25min vs 1.5h for complex hosts).
  - User-visible message shows target reduction: `Nuclei: 25 -> 8 targets (audit focus)`.

### Fixed

- **Color Bug Fix (from v4.15.1)**: [INFO] messages no longer appear white during progress bar display.
  - Root cause: Rich markup `[INFO]` was interpreted as an unknown tag.
  - Fix: Use Rich `Text()` objects for reliable color output.

## [4.15.0] - 2026-01-19

### Added

- **HyperScan Progress Bar**: Visual progress bar (magenta) showing host completion during HyperScan-First discovery phase.
- **Nuclei Auto-Fast Profile**: Automatic detection of hosts with 3+ HTTP ports, switching to "fast" profile (CVE-only templates) to prevent timeouts.

### Fixed

- **HyperScan True Parallelism**: Removed SYN scan lock that was serializing scans. RustScan/asyncio now run in true parallel mode.
- **Minimalist Terminal Emojis**: Replaced colorful emojis with monochrome Unicode alternatives:
  - `✅` -> `✔`
  - `❌` -> `✖`
  - `⚠️` -> `⚠`
- **Test Fixes**: Updated `test_session_log.py` to use new minimalist emojis.

### Testing

- Added `test_hyperscan_start_sequential_key_en` and `test_hyperscan_start_sequential_key_es` to verify i18n keys.

## [4.14.0] - 2026-01-19

### Added

- **Device-Aware Remediation**: New templates in `playbook_generator.py` for AVM (FRITZ!), Linux, Cisco/Network, and Windows devices.
  - Embedded devices (e.g., FRITZ!Box) now suggest firmware updates via web UI instead of `apt/yum`.
  - Network devices suggest IOS/firmware updates.
  - Linux servers retain `apt/yum` guidance.
- **Model-Specific CVE Matching**: Enhanced `verify_vuln.py` to support `expected_models` and `false_positive_models`.
  - Implemented for **CVE-2024-54767** (AVM Unauth Access): matches only `7530`, excludes `7590` and Repeaters.
- **Technical Detail Fallback**: `evidence_parser.py` now generates robust observations from service versions, banners, and headers when specific tool output is missing.

### Fixed

- **Playbook Titles**: Fixed issue where finding titles containing URLs (e.g. `http://...`) were used as playbook titles. Now falls back to descriptive titles or generic names.
- **Wizard UX**: Added logic to prompt for manual configuration if user declines to load credentials from keyring.
- **Wizard Styling**: Enhanced wizard menu with professional colors (Dim for navigation, Bold Cyan for selection).
- **Code Robustness**: Completed exhaustive audit of `playbook_generator.py`:
  - Fixed `{host}` placeholder logic in steps.
  - Added strict type safety checks for vendor and device type processing.

## [4.13.2] - 2026-01-18

### Fixed

- **HTML Report References**: Fixed key mismatch (`reference` vs `references`) causing missing technical details in Findings section.
- **CVE-2022-26143 False Positive**: Enhanced FRITZ!OS detection to include response body, not just Server header.
- **Nuclei Rich Data**: Now extracts `impact`, `remediation`, `cvss_score`, `cvss_metrics`, and `extracted_results` from Nuclei findings.
- **Empty Observations**: Added fallback to use vulnerability description when `parsed_observations` is empty.
- **Source Attribution**: Changed default source from `unknown` to `redaudit` for auto-generated findings. Added WhatWeb detection.

## [4.13.0] - 2026-01-17

### Added

- **Dead Host Retries**: New `--dead-host-retries` CLI flag to abandon hosts after N consecutive timeouts (default: 3). Prevents scan stalls on unresponsive hosts.
- **ConfigurationContext Integration**: Added `dead_host_retries` property to typed config wrapper.

### Fixed

- **i18n Nuclei Estimates**: Corrected Nuclei profile time estimates in wizard:
  - `fast`: ~15min -> ~30-60min
  - `balanced`: ~30min -> ~1h
- **Wizard Text Truncation**: Shortened Spanish wizard profile descriptions to prevent terminal truncation on narrow displays.

## [4.12.1] - 2026-01-17

### Added

- **Topology Enrichment**: ARP scan results in topology phase now perform OUI lookup to resolve "(Unknown)" vendors.
- **Nuclei Optimization**: Added `rate_limit` and `batch_size` configuration to Nuclei profiles.
  - `fast` profile now runs at 300 rps (was 150) with batch size 15 (was 10) for faster execution.
- **Wizard Clarity**: Updated Express/Standard profile descriptions to clearly state scan depth (discovery vs vuln).

### Fixed

- Fixed interaction between Nuclei profile defaults and explicit parameters (explicit parameters now correctly override profile defaults).
- Fixed typing issues (mypy) in Nuclei module with proper `TypedDict` for profiles.

## [v4.12.0] - 2026-01-17

### Added

- **Profile-Based Tool Gating**: The Nuclei profile (`--profile`) now gates Nikto execution:
  - `fast`: Skips Nikto entirely for maximum speed.
  - `balanced`: Skips Nikto on infrastructure devices (routers, switches, APs).
  - `full`: Runs Nikto on all web hosts (original behavior).
- **Enhanced Infrastructure Detection**: Improved `is_infra_identity()` to detect more network device patterns (Fritz!Box, MikroTik, Ubiquiti, Synology, QNAP, etc.).

### Changed

- **Performance Optimization**: Vuln scan phase now respects the Nuclei profile to reduce scan time on networks with many infrastructure devices.
- **Nikto Gating Logic**: Moved from `_should_run_app_scans()` to dedicated `_should_run_nikto()` method for clearer separation of concerns.

## [v4.11.0] - 2026-01-17

### Added

- **Nuclei Profile Selector**: Introduced optimized scanning profiles (`--profile`) to balance speed and coverage:
  - `full`: All templates (default behavior).
  - `balanced`: High-impact tags only (cve, rce, exposure, misconfig) - ~4x faster.
  - `fast`: Critical checks only (cve, critical) - ~10x faster.
- **Improved IoT Visibility**:
  - **WiZ Protocol Support**: Automatically detects and reports WiZ smart bulbs via UDP port 38899 injection, solving "zero ports found" issue for these devices.
  - **Closed-Port IoT**: Documentation updated to clarify handling of devices that respond to multicast/UPnP but have no open TCP ports.
- **Enhanced Identity Engine**:
  - **OUI Database**: Massive update from 46 to **38,911 vendors** using Wireshark's manufacturer database, significantly reducing "Unknown" vendor tags.

### Changed

- **Nuclei Optimization**:
  - Reduced batch size from 25 to 10 targets to prevent timeouts.
  - Increased timeout from 300s to 600s per batch for better reliability in dense networks.
  - Implemented "partial success" logic: findings are reported even if some batches timeout.
- **Timeouts**: Confirmed satisfactory timeouts for Nikto (330s) and TestSSL (90s).

## [v4.10.1] - 2026-01-16

### Fixed

- **Inconsistent Host Enrichment**: Fixed an issue where hosts discovered via Route Following (SNMP Topology) were not being enriched with CVE data, causing them to appear incomplete in reports compared to primary targets.
- **Import Error**: Resolved a potential `NameError` related to local imports of `enrich_host_with_cves` in the auditor module.
- **Code Cleanup**: Moved local imports to top-level for better maintainability and scope visibility.

## [v4.10.0] - 2026-01-16

### Added

- **Advanced L2/L3 Discovery**:
  - **SNMP Topology**: Authenticated queries for router tables, ARP tables, and interfaces (`--snmp-topology`).
  - **Route Following**: Automatic scope expansion based on discovered routing tables (`--follow-routes`).
  - **Passive L2 Discovery**:
    - **LLDP**: System/Port info via `tcpdump` (macOS/Linux) and `lldpctl`.
    - **CDP**: Cisco discovery via `tcpdump`.
    - **VLAN Detection**: 802.1Q tags from `ifconfig`/`ip link` and passive sniffing.
  - **Wizard Integration**: Interactive prompts for topology and route following settings.

### Fixed

- **Critical**: Resolved `AttributeError: 'set' object has no attribute 'append'` in `Host.tags` handling during HyperScan enhancement.

## [v4.9.1] - 2026-01-16

### Added

- **Quick Wins Implementation**:
  - **IoT UDP Visibility**: Specialized UDP ports (e.g., WiZ 38899) discovered by HyperScan are now properly exported to final reports.
  - **Honeypot Detection**: New `honeypot` tag for hosts with excessive open ports (>100).
  - **No-Response Tagging**: Hosts that fail Nmap scanning are tagged with `no_response:nmap_failed` for better status granularity.

### Fixed

- **Nuclei Wizard Prompt**: Fixed i18n key `nuclei_enable_q` to use existing `nuclei_q` key, displaying translated text instead of raw key.

### Changed

- **Code Cleanup**: Removed dead code `masscan_scanner.py` (replaced by RustScan in v4.8.0).

### Documentation

- **VLAN Limitations**: Added 802.1Q VLAN detection limitations to USAGE docs (EN/ES).

## [v4.9.0] - 2026-01-16

### Added

- **Hidden Network Detection**: New `detect_routed_networks()` in `net_discovery.py`.
  - Parses `ip route` and `ip neigh` to discover non-local routed networks.
  - Interactive wizard prompt: asks user to include discovered hidden networks in scan scope.
  - New CLI flag `--scan-routed` for non-interactive mode (auto-adds routed networks to targets).

### Changed

- **Wizard Network Selection**: `ask_network_range()` now detects and offers hidden routed networks.

### Documentation

- Documented VLAN isolation limitations (802.1Q VLANs not discoverable without SNMP/switch access).
- Updated `task.md` with user network topology (Vodafone VLAN 100/105 via Zyxel switch).

## [v4.8.1] - 2026-01-16

### Fixed

- Restore interactive Nuclei enable prompt in Exhaustive profile (wizard).

## [v4.8.3] - 2026-01-16

### Fixed

- **Installer Architecture**: Added ARM64/aarch64 architecture detection to support Raspberry Pi and Apple Silicon VMs.
  - Previously attempted to download amd64 .deb on all platforms.
  - Now gracefully falls back to nmap/apt if RustScan release asset is missing for the architecture.

## [v4.8.2] - 2026-01-16

### Fixed

- **RustScan Port Range**: Force scanning of full port range (1-65535) in HyperScan phase.
  - Previously defaulted to RustScan's top 1000 ports, missing services on non-standard ports.
  - Added range parameter to `rustscan.py` and `hyperscan.py`.

## [v4.8.0] - 2026-01-16

### Added

- **RustScan Integration**: New `rustscan.py` module for ultra-fast port discovery.
  - RustScan finds all 65535 ports in ~3 seconds (vs 142s masscan, 6s nmap).
  - Automatic nmap fallback if RustScan not installed.
  - Added to installer (`redaudit_install.sh`) as optional but recommended dependency.

### Changed

- **HyperScan-First Architecture**: Replaced masscan with RustScan as primary port scanner.
  - Based on benchmark: RustScan+nmap (38s) vs masscan (142s) vs nmap-only (43s).
  - Full port range discovery now significantly faster on physical networks.

- **Nuclei OFF by Default**: Nuclei template scanner now disabled by default.
  - Use `--nuclei` flag to enable explicitly.
  - Reason: Slow on web-dense networks with marginal value for network audits.
  - Still available via `--nuclei` flag when needed for specific web security testing.

### Documentation

- Added `scan_results_private/HYPERSCAN_INVESTIGATION_2026-01-16.md` with full benchmark data.

## [v4.7.2] - 2026-01-15

### Fixed

- **Nuclei Timeout (Critical)**: Fixed batch timeout minimum in nuclei.py from 60s to 300s, and base timeout from 300s to 600s. The 60s minimum was causing 100% batch timeout rate. Also added nuclei-specific timeout (600s) in command_runner.py as fallback.
- **NVD API 404**: Skip retries immediately on 404 responses (CPE not found is not retryable). Reduces unnecessary API calls and log spam.

## [v4.7.1] - 2026-01-15

### Fixed

- **Critical**: Fixed masscan fallback regression in v4.7.0 where `or True` prevented scapy fallback when masscan returned 0 ports. Docker networks (172.x.x.x) now correctly fall back to scapy for accurate port detection.

### Documentation

- Added "Masscan and Docker Bridge Networks" troubleshooting section to `DOCKER.md` and `DOCKER.es.md` explaining the automatic scapy fallback behavior.

## [v4.7.0] - 2026-01-15

### Added

- **HyperScan Masscan Integration**: New `masscan_scanner.py` module provides orders-of-magnitude faster port discovery.
  - `masscan_sweep()` scans top 10,000 ports in seconds vs minutes with scapy.
  - Integrated as primary backend in `hyperscan_full_port_sweep()`.
  - Automatic fallback to asyncio TCP connect if masscan unavailable.
  - Reduces HyperScan-First from ~30 minutes to ~10 seconds for 36 hosts.

## [v4.6.34] - 2026-01-15

### Fixed

- **Nuclei**: Fixed Ctrl+C hang during long scans by adding KeyboardInterrupt handler with graceful process termination.
- **Nuclei**: Reduced batch size from 25 to 10 targets for faster parallel completion and fewer timeouts.
- **HyperScan**: Fixed persistent 0.5s timeout override; now explicitly uses 1.5s for better port detection accuracy.
- **HyperScan SYN Contention Fix**: Added `threading.Lock()` to serialize scapy SYN scans, fixing critical regression where parallel workers caused raw socket conflicts (0 ports detected on Docker networks).
- **Net Discovery**: Parallelized `_redteam_rpc_enum`, `_redteam_snmp_walk`, `_redteam_ldap_enum`, and `_redteam_smb_enum` (enum4linux) to eliminate serial blocking (10+ minute delays on large networks).

## [v4.6.33] - 2026-01-15

### Fixed

- **Net Discovery**: Fixed Net Discovery duration (timeouts reduced), HyperScan accuracy (timeout increased), and "UDP probes" localization.
- **Parallel Discovery**: Fixed thread safety in parallel discovery progress bars and removed unsafe CLI printing.

## [v4.6.32] - 2026-01-15

### Performance

- **Parallel Net Discovery**: All discovery protocols (DHCP, ARP, mDNS, etc.) now run concurrently.

## [v4.6.31] - 2026-01-15

### Performance

- **HyperScan Parallelism**: Converted sequential pre-scan to parallel (up to 8 workers) with adaptive FD batching.

## [v4.6.30] - 2026-01-15

### Safety

- **Zombie Reaper**: Implemented native `pkill` cleanup to prevent orphaned Nmap/Nuclei processes on interruption.
- **Resource Audit**: Verified FD safety and thread exception handling.

## [v4.6.29] - 2026-01-15

### Performance

- **Thread Uncapping**: Increased `MAX_THREADS` from 16 to 100 to utilize modern hardware.
- **Deep Scan**: Removed 50-thread cap to respect global `MAX_THREADS` limit.

### Fixed

- **Config**: Added missing `nuclei_timeout` to `ConfigurationContext`.

## [v4.6.28] - 2026-01-15

### Fixed

- **Critical Stability**: Removed global `socket.setdefaulttimeout()` usage in `network_scanner.py`. Previously, reverse DNS lookups could inadvertently set a timeout for ALL active threads and sockets in the application, causing random timeouts in Nuclei, SSH, and HTTP connections.

## [v4.6.27] - 2026-01-15

### Fixed

- **HyperScan Performance**: Fixed a critical logic flaw where closed ports (RST) were treated as "timeouts" by the adaptive throttler. This caused the scan speed to throttle down to minimum (100 batch) instead of accelerating (20k batch), explaining the "1 minute per host" delay. Scans are now substantially faster.

## [v4.6.26] - 2026-01-15

### Fixed

- **Progress Bar Jitter**: Fixed a UI bug where parallel Nuclei batches would overwrite each other's progress, causing the progress bar to jump erratically. Implemented centralized progress aggregation for smooth tracking.

## [v4.6.25] - 2026-01-15

### Fixed

- **Parallel Concurrency Fix**: Added thread locking for shared file I/O and statistics in Nuclei scans to prevent race conditions during parallel execution.
- **CLI Parallelism**: Enabled parallel batch execution for standard CLI users (Rich progress bar), previously limited to API consumers.

## [v4.6.24] - 2026-01-15

### Changed

- **Nuclei Performance Overhaul**: Reduced default batch size 25->10, removed infinite retry loop bug, added up to 4 parallel batch execution via ThreadPoolExecutor. Expect ~4x faster Nuclei scans on large networks.

## [v4.6.23] - 2026-01-14

### Added

- **Nuclei Retry on Timeout**: On first timeout, retry batch with 1.5x timeout before splitting. Reduces false failures on slow networks.
- **Test Coverage**: Added 8 new tests for v4.6.21-23 features (X-Frame-Options, IoT lwIP, FTP CVE injection).

## [v4.6.22] - 2026-01-14

### Added

- **FTP CVE Tagging**: Detected backdoors (vsftpd 2.3.4, etc.) now inject CVE records into `port.cves` for automatic JSONL propagation.
- **SMB Credential Spray**: Try all keyring SMB credentials until one succeeds, matching SSH spray pattern. Uses new `_resolve_all_smb_credentials()` method.

## [v4.6.21] - 2026-01-14

### Fixed

- **X-Frame-Options Severity**: Added `anti-clickjacking.*x-frame-options` and `x-frame-options.*not present` patterns to SEVERITY_OVERRIDES. Nikto findings now correctly classified as Low instead of High.
- **IoT lwIP False Positive**: Added heuristic in `calculate_risk_score` to detect IoT devices with >20 open ports (lwIP stack responds SYN-ACK to all probes). Risk capped at 30 for manual review.

## [v4.6.20] - 2026-01-14

### Added

- **Nuclei Timeout Flag**: New `--nuclei-timeout` CLI flag to configure batch timeout (default 300s). Useful for Docker/slow networks where default timeout causes partial scans.

### Fixed

- **vsftpd 2.3.4 Backdoor Detection**: Fixed detection of CVE-2011-2523 backdoor by combining service+product+version+banner fields in `calculate_risk_score`.
- **Title Consistency**: JSONL export now uses `descriptive_title` for both `title` and `descriptive_title` fields, matching HTML report behavior.
- **Unified Title Generation**: Consolidated `_extract_title` functions from `jsonl_exporter` and `html_reporter` into single `extract_finding_title` in `siem.py`, removing 170 lines of duplicated code.

### Improved

- **Code Quality**: Added `extract_finding_title` with proper fallback chain: descriptive_title, Nuclei template_id, CVE IDs, parsed_observations, nikto_findings, port-based fallback.

## [v4.6.19] - 2026-01-14

### Added

- **Finding Prioritization**: New `priority_score` (0-100) and `confirmed_exploitable` fields to better rank vulnerabilities.
- **Classic Vulnerability Detection**: Automatic detection of known backdoored services (vsftpd 2.3.4, UnrealIRCd 3.2.8.1, etc.) from banner analysis.
- **Report Quality**: New `confidence_score` (0.0-1.0) for findings based on verification signals.
- **Improved Titles**: Better title generation for findings, detecting specific vulnerabilities (BEAST, POODLE) and providing clearer fallback titles (e.g., "HTTP Service Finding").
- **JSONL Export**: Added quality fields (`confidence_score`, `priority_score`, `confirmed_exploitable`) to JSONL output for SIEM ingestion.

### Improved

- **Wizard UI**: Credential summary now displays the count of spray list entries (e.g., `(+5 spray)`).
- **Severity Mapping**: Refined mapping for generic scanner findings to reduce noise (e.g., lowering severity for version disclosures).

## [v4.6.18] - 2026-01-13

### Added

- **SSH Credential Spray**: Try all credentials from keyring spray list until authentication succeeds. Enables single spray list for networks with multiple SSH auth requirements.

### Fixed

- **Nuclei Partial Output**: Persist partial findings when batches timeout at maximum split depth instead of leaving output empty.
- **NVD URL Encoding**: URL-encode keyword search parameters to fix queries with spaces.

## [v4.6.17] - 2026-01-13

### Fixed

- **Keyring Under Sudo**: Preserve DBus context when loading the invoking user's keyring to surface saved credentials.

## [v4.6.16] - 2026-01-13

### Improved

- **Nuclei Reliability**: Adaptive batch timeouts, recursive splits, and optional per-request timeout/retries to reduce partial runs.

## [v4.6.15] - 2026-01-13

### Improved

- **Nuclei Progress Stability**: Keep target progress monotonic across batch retries and timeouts.

### Fixed

- **Host Report Consistency**: Populate `hosts[].asset_name` and `hosts[].interfaces` from unified assets.

## [v4.6.14] - 2026-01-13

### Added

- **Auth Wizard Cancel**: Allow canceling credential prompts to exit auth setup cleanly.

### Improved

- **Wizard Navigation Label**: Rename "Go Back" to "Cancel" and use warning color for navigation entries.

### Fixed

- **Keyring Under Sudo**: Detect saved credentials from the invoking user when running with sudo.
- **Report Footer Year**: Update HTML report license footer to 2026.

## [v4.6.13] - 2026-01-12

### Added

- **Wizard Targets**: Show normalized targets with estimated host counts before execution.

### Improved

- **Nuclei Progress**: Track target-based progress within batches to avoid frozen bars.
- **Vuln Progress**: Display explicit Nikto timeout status when it exceeds its budget.

### Fixed

- **Asset Classification**: Chromecast-style services override generic router hints for media devices.
- **Web Identity**: Recognize OWASP Juice Shop titles as server-class assets.
- **Run Manifest**: Mark `run_manifest.json` as partial when Nuclei timeouts occur.

## [v4.6.12] - 2026-01-12

### Improved

- **Nuclei Progress**: Show time-based progress movement within each batch, including elapsed time, to avoid frozen bars.

## [v4.6.11] - 2026-01-12

### Added

- **Agentless HTTP Source**: Track HTTP identity origin (`http_source`, `upnp_device_name`) to distinguish UPnP hints from real HTTP signals.

### Changed

- **Nuclei Progress**: Emit heartbeat updates during long batches to show ongoing activity and elapsed time.

### Fixed

- **HTTP Identity Gating**: Ignore UPnP-only titles for web scan gating and identity scoring; allow HTTP probes to override UPnP hints.
- **Web Enrichment**: Propagate HTTP server headers from web vuln enrichment into agentless fingerprints.

## [v4.6.10] - 2026-01-12

### Added

- **Wizard Targets**: Manual target entry accepts comma-separated CIDR/IP/range values and normalizes ranges to CIDR blocks.
- **CLI Targets**: Accept IP ranges and normalize single IPs to /32 for consistent scanning.

### Changed

- **Docs**: Updated README/usage/manual and cleaned roadmap ordering with emoji removal.

## [v4.6.9] - 2026-01-12

### Changed

- **Deep Scan**: Use HTTP title/server and device-type evidence to avoid unnecessary deep scans when identity is already strong.
- **Web App Scanning**: Skip sqlmap/ZAP on infrastructure UIs when identity indicates router/switch/AP devices.

### Fixed

- **Nuclei Reporting**: Mark partial runs when batches time out and surface timeout/failed batch indexes in reports.

## [v4.6.8] - 2026-01-12

### Fixed

- **Vuln Progress**: Stop updating progress bars after a host finishes to avoid misleading movement.
- **Web Tags**: Add the `web` tag when `web_ports_count` is present, even if port flags are missing.

## [v4.6.7] - 2026-01-11

### Fixed

- **Auth Scans**: Avoid keyring credential lookups during port scans when auth is disabled.
- **Session Logs**: Deduplicate rich progress-bar redraws to reduce log noise.

## [v4.6.6] - 2026-01-11

### Changed

- **UX**: Added "Trust HyperScan" prompt to the Exhaustive profile (default: No).

## [v4.6.5] - 2026-01-11

### Fixed

- **Updater**: Force `VERSION` to match the target tag during updates to avoid stale banners.
- **Version Resolution**: Prefer packaged `VERSION` over installed metadata to prevent pip shadowing.
- **Update Flow**: Block non-root system updates for `/usr/local/bin/redaudit` to avoid partial installs.

## [v4.6.4] - 2026-01-11

- **UX**: Visible "Trust HyperScan" prompt in Standard profile (was hidden/auto-true).

## [v4.6.3] - 2026-01-11

### Changed

- **UX**: Added missing "Trust HyperScan" prompt to Wizard (Step 2).
- **UX**: Enabled Trust HyperScan by default in "Express" and "Standard" profiles.

## [v4.6.2] - 2026-01-11

### Added

- **Trust HyperScan Optimization (Quiet Hosts)**: Now handles "mute" hosts (0 ports) intelligently. Instead of falling back to a full 65k port scan, it performs a sanity check on top 1000 ports if "Trust HyperScan" is enabled.

## [4.6.0] - 2026-01-11

### Added

- **Trust HyperScan Optimization**: New ability to reuse HyperScan discovery results for the Deep Scan phase, bypassing the slow `-p-` scan.
  - Added CLI flag `--trust-hyperscan` / `--trust-discovery`.
  - Added interactive prompt in the setup Wizard.
  - Drastically reduces scan time for identified hosts by scanning only known ports.

## [4.5.18] - 2026-01-11

### Fixed

- **Lab Setup (Hotfix)**: `setup_lab.sh` now force-recreates the `target-windows` (.30) container using the correct `elswork/samba` configuration, fixing usage of broken/outdated images.

## [4.5.17] - 2026-01-11

### Fixed

- **Scan Logic (BUG-01)**: HyperScan ports are now strictly preserved even if deep scan phase fails or returns zero ports due to timeouts.
- **Router Scanning (UX-03)**: Optimized deep scan logic for infrastructure devices:
  - Well-identified routers (strong identity, known vendor, <= 20 ports) now skip redundant Deep Scan.
  - Suspicious or ambiguous hosts ALWAYS receive the full 65k port sweep.
  - Solves the 25+ minute router scan issue while adhering to the strict security diagram.
- **Input Handling**: Fixed `Ctrl+C` crash in wizard (graceful exit).
- **CLI**: Added missing `--verbose` / `-v` argument.

### Documentation

- **Installation**: Updated README to clarify that RedAudit has a native auto-update mechanism via the wizard (`sudo redaudit`).
- **Compatibility**: Added specific guidance for Ubuntu 24.04+ (Noble) regarding pip restrictions.

## [4.5.16] - 2026-01-10

### Fixed

- **Smart Scan**: Preserve HyperScan-discovered ports when nmap underreports due to timing/networking issues.
- **SIEM Tags**: `deep-scanned` tag now only added when deep scan was actually executed.

## [4.5.15] - 2026-01-10

### Fixed

- **Smart Scan**: Fixed Ghost Identity detection in `auditor_scan.py` (v4.5.14 fix was in wrong code path).
- **SSH Auth**: Changed `auth_ssh_trust_keys` default to `True` for automated scanning.

## [4.5.14] - 2026-01-10

### Fixed

- **SSH Auth**: Implemented robust `PermissivePolicy` to prevent `Server not found in known_hosts` errors caused by strict checks or write permission issues.
- **Smart Scan**: Fixed "Ghost Identity" issue where hosts with Phase 0 hints (e.g., SNMP) but zero open ports failed to trigger Deep Scan.

## [4.5.13] - 2026-01-10

### Fixed

- **Critical**: Resolved `AttributeError: 'Host' object has no attribute 'get'` in Authenticated Scanning phase. The scanner now correctly handles Host objects when accessing IP and storing SSH results.
- **Docs**: Updated `LAB_SETUP` guides with language badges and clearer distinctions between Victim Lab (Docker supported) and Auditor Machine (Native Linux recommended).

## [4.5.12] - 2026-01-10

### Fixed

- **Smart Pip Installation (PEP 668 Support)**:
  - The installer now automatically detects failures due to "externally managed environments" (common in Ubuntu 24.04 and recent Kali versions) and retries installation with the `--break-system-packages` flag if supported. This ensures dependencies like `pysnmp` and `impacket` are correctly installed even when absent from APT repositories.

## [4.5.11] - 2026-01-10

### Fixed

- **Universal Installer Compatibility**:
  - Made `python3-pysnmp` installation optional/warn-only in the APT step. This prevents the installer from aborting on distributions that removed this package (e.g., Ubuntu Noble 24.04).
  - Fixed a duplicated apt installation line in `redaudit_install.sh`.

## [4.5.10] - 2026-01-10

### Improved

- **Installer Robustness**:
  - Added `python3-pysnmp` to APT dependencies (preferred over pip on Debian systems).
  - Removed `--quiet` from pip installation to expose errors if package installation fails.

## [4.5.9] - 2026-01-10

### Fixed

- **CI/Linting**: Suppressed false positive security warnings (Bandit) in `scripts/seed_keyring.py` for hardcoded lab credentials.

## [4.5.8] - 2026-01-10

### Fixed

- **Root Keyring Support (Headless)**: Added support for `keyrings.alt` to handle credential storage when running as root without a desktop session (common in servers/Labs).
  - **Installer**: Added `keyrings.alt` to dependencies.
  - **Core**: `redaudit` and `seed_keyring.py` now fallback to `PlaintextKeyring` (file-based) if the system keyring is unavailable.

## [4.5.7] - 2026-01-10

### Fixed

- **Credential Loading (Sudo Context)**: Fixed an issue where credentials seeded by a regular user were not visible to `sudo redaudit`.
  - **Updater**: Auto-seed now runs as root during update (preserving `sudo` context).
  - **Seeder Script**: Added warning if run as non-root to prevent confusion.
- **CI/Test Stability**: Added robust integration tests for credential loading flow (`tests/core/test_credentials_loading_flow.py`).

## [4.5.6] - 2026-01-10

### Added

- **Lab Setup Automation**: Added `scripts/setup_lab.sh` to automate Docker lab provisioning.
  - Commands: `install`, `start`, `stop`, `remove`, `status`.
  - Provisions 11 vulnerable targets (Juice Shop, Metasploitable, Windows Sim, SCADA, AD, etc.).
- **Lab Documentation**: Added `docs/LAB_SETUP.md` and `docs/LAB_SETUP_ES.md`.
  - Comprehensive guide on setting up the testing environment.
  - Linked from main README.

## [4.5.5] - 2026-01-10

### Added

- **Lab Credentials Script (Spray Mode)**: Added `scripts/seed_keyring.py` containing ALL lab credentials.
  - Pre-populates keyring with SSH (3), SMB (3), and SNMP (1) credentials.
  - Includes reference to web credentials.

- **Updater Auto-Seed**: Setup wizard update (Option 2) now automatically runs `seed_keyring.py` if present.
  - Ensures seamless credential setup after update.

## [4.5.4] - 2026-01-10

### Added

- **B5: Credential Loading from Keyring**: Wizard now detects saved credentials and offers to load them at scan start.
  - Added `has_saved_credentials()` and `get_saved_credential_summary()` to `KeyringCredentialProvider`.
  - Added `_check_and_load_saved_credentials()` to wizard authentication flow.
  - Eliminates need to re-enter credentials for subsequent scans.

## [4.5.3] - 2026-01-10

### Added

- **Secure Credential Storage (Keyring)**: `keyring` package now included as core dependency for secure credential storage via OS keychain (Linux Secret Service, macOS Keychain, Windows Credential Vault).
  - Added to main dependencies and installer (`python3-keyring` apt + pip).

- **B5: Credential Loading from Keyring**: Wizard now detects saved credentials and offers to load them at scan start.
  - Added `has_saved_credentials()` and `get_saved_credential_summary()` to `KeyringCredentialProvider`.
  - Added `_check_and_load_saved_credentials()` to wizard authentication flow.

### Fixed

- **Scan Audit Bugs (B2/B3/B4)**:
  - **B2**: Vuln progress bars now always reach 100% (added final loop in `auditor_vuln.py`).
  - **B3**: Heartbeat INFO tag changed from `[grey50]` to `[cyan]` for proper visibility.
  - **B4**: SSH detection in authenticated scans now handles `Host` objects (not just dicts), fixing "No SSH-enabled hosts found" false negatives.

## [4.5.2] - 2026-01-10

### Added

- **Multi-Credential Support (Phase 4.1.1)**:
  - Added `Universal` authentication mode in wizard and `--credentials-file` flag support.
  - Automatic protocol detection (SSH/SMB/SNMP/RDP/WinRM) based on open ports.
  - Added `CredentialsManager` for secure credential handling and template generation (`--generate-credentials-template`).
  - Added "Zero-Context Audit" fixes: `ask_choice_with_back` for safe menu navigation and refactored `auditor.py` to use shared auth logic.

### Changed

- **Wizard**:
  - Refactored Authentication workflow to support `Universal` vs `Advanced` modes.
  - Added "Go Back" (`<`) navigation support to critical menus to prevent user entrapment.
  - Added UI hints for protocol detection strategy.

### Fixed

- **Authentication**: Fixed critical logic gap where `auditor.py` legacy code ignored wizard-configured credentials.
  - Now uses unified `ask_auth_config` entry point for both interactive and programmatic flows.

## [4.5.0] - 2026-01-09

### Added

- **Authenticated Scanning (SSH)**: Deep interrogation of Linux hosts (Kernel, Packages, Uptime).
- **Authenticated Scanning (SMB/WMI)**: Windows enumeration (OS, Domain, Shares, Users) via `impacket`.
- **Authenticated Scanning (SNMP v3)**: Secure network device auditing with Auth/Priv protocols.
- **Lynis Integration**: Remote execution of hardening audits via SSH.
- **Interactive Wizard**: New Step 8 for Authentication configuration.
- **Keyring Integration**: Secure storage for scan credentials.

### Changed

- **Wizard**: Updated flow to 9 steps to accommodate authentication options.
- **Docs**: Comprehensive updates to MANUAL and USAGE guides.

### Fixed

- **RecursionError**: in `AuditorRuntime.__getattr__`.
- **Tests**: Various fixes for Mock iterators in wizard tests.
- **Mypy**: Type safety improvements in Auth modules.

## [4.4.5] - 2026-01-09

### Improved

- **Code Coverage Push**: Achieved 100% coverage in `topology.py` and >94% in `updater.py`, boosting total project coverage to ~89%.
  - Added robust test scenarios for topology loops, network crashes, and edge-case exceptions.
  - Refactored updater tests with dynamic mocking for stability.
- **Stability**: Resolved pre-commit hook interventions and formatting inconsistencies in test files.

## [4.4.4] - 2026-01-09

### Improved

- **Code Coverage Push**: Significantly increased test coverage across core modules (reached ~90% total coverage).
  - Added targeted tests for `siem.py` (risk breakdown, tool-specific severity mapping, CEF generation).
  - Added tests for `syn_scanner.py` (scapy integration paths, raw socket failures).
  - Added tests for `reporter.py` (file creation failures, encrypted result verification).
  - Added tests for `auditor.py` and `hyperscan.py` (initialization paths, connection logic).

## [4.4.3] - 2026-01-08

### Fixed

- **mDNS Log Noise**: Suppressed excessive `TimeoutError` tracebacks in `_run_low_impact_enrichment` by handling them as expected behavior (debug level logging).
- **Agentless Verification**: Fixed data loss where `Host` dataclass objects were not correctly handled during index creation and fingerprint merging, ensuring agentless probe results are properly attached to hosts.
- **SNMP Logic**: Fixed regex syntax in `_run_low_impact_enrichment` for safer SNMP parsing.

### Improved

- **Test Coverage**: Added targeted unit tests for `redaudit/core/auditor_scan.py` covering mDNS/DNS/SNMP fallback paths and exception handling.

### Fixed

- **CVE-2022-26143 False Positive on FRITZ!Box Routers**: Fixed critical pipeline integration bug where the Nuclei false positive filter was not receiving host data, causing router endpoints (AVM FRITZ!Box) to be incorrectly flagged as vulnerable to Mitel MiCollab CVE-2022-26143.
  - Root cause: `filter_nuclei_false_positives()` was not receiving `host_records` parameter in `auditor.py`, preventing CPE-based validation.
  - Added `fritz!os` to explicit false positive vendor list for improved header matching.
  - Removed duplicate `server_header` variable assignment in `check_nuclei_false_positive()`.
  - New parameter: `host_records` in `filter_nuclei_false_positives()` enables full host data flow for accurate validation.

## [4.4.1] - 2026-01-08

### Added

- Local CI parity script `scripts/ci_local.sh` to run pre-commit and pytest across Python 3.9-3.12.

### Fixed

- Python 3.9 dev lock now selects compatible versions for iniconfig, pytest-asyncio, markdown-it-py, pycodestyle, and pyflakes to avoid resolver conflicts.
- Runtime lock now selects a Python 3.9 compatible markdown-it-py when running under 3.9.

### Changed

- Unit tests for complete scan flows disable HyperScan-first to keep runtime bounded without affecting production behavior.

## [4.4.0] - 2026-01-08

### Added

- **Smart-Throttle (Adaptive Congestion Control)**: New AIMD-based rate limiting algorithm (`SmartThrottle`) in HyperScan. It dynamically adjusts the `batch_size` based on network timeout feedback, preventing packet loss on congested networks and accelerating on stable ones.
- **Generator-based Targeting**: Refactored `HyperScan` to use lazy generators for target expansion. This allows scanning massive networks (e.g., /16 subnets) without multi-gigabyte memory spikes.
- **Scalability Improvements**: Optimized `auditor_scan.py` host collection to streamline processing of large result sets.
- **Distributed Architecture Design**: Added design documentation for future Controller/Worker distributed scanning mode.
- **AsyncIO Migration Investigation**: Completed feasibility study for full non-blocking I/O migration (deferred to v5.0).

### Changed

- **HyperScan**: Now uses `itertools.product` for probe generation.
- **UI**: detailed progress bar in HyperScan now shows real-time throttling status (▼/▲) and effective speed.

## [4.3.3] - 2026-01-08

### Fixed

- **Data Integrity**: Vulnerability findings (from Nikto, etc.) are now correctly attached to `Host` objects in memory. This fixes the issue where vulnerabilities were missing from JSON reports and Risk Scores were calculated as 0 despite finding weaknesses.
- **UI UX**: Fixed a visual glitch where the "heartbeat" status message ("Net Discovery in progress...") would duplicate IP lines in the wizard UI. It now prints safely to the progress console.

## [4.3.2] - 2026-01-08

### Fixed

- **Release Integrity**: Fixed version mismatch between `pyproject.toml` and `VERSION` file that caused CI failures in v4.3.1.
- **Maintenance**: This release supersedes v4.3.1 (which failed CI self-checks).

## [4.3.1] - 2026-01-08 [YANKED]

### Fixed

- **CI Test Regressions**: Resolved mock mismatches and architecture alignment for Wizard, Net Discovery, and Smart Scan Spec V1 tests.
  - Patched `_run_cmd_suppress_stderr` in net discovery tests.
  - Updated Deep Scan acceptance tests to reflect v4.2 decoupled architecture.
  - Fixed `StopIteration` in wizard interactive tests by expanding mock inputs.

## [4.3.0] - 2026-01-07

### Added

- **HyperScan SYN Mode**: Optional SYN-based port scanning using scapy for ~10x faster discovery.
  - New CLI flag: `--hyperscan-mode auto|connect|syn`
  - New module: `redaudit/core/syn_scanner.py` with scapy integration
  - Auto mode: Tries SYN if root + scapy available, otherwise falls back to connect
  - Stealth timing uses connect mode (stealthier than SYN)
  - Wizard integration: All profiles (Express/Standard/Exhaustive/Custom) support mode selection

- **Risk Score Breakdown Tooltip**: HTML reports now show detailed risk score components on hover.
  - Components: Max CVSS, Base Score, Density Bonus, Exposure Multiplier
  - New function: `calculate_risk_score_with_breakdown()` in `siem.py`

- **Identity Score Visualization**: HTML reports display identity_score with color coding.
  - Green (≥3): Well-identified host
  - Yellow (=2): Partially identified
  - Red (<2): Weak identification (triggered deep scan)
  - Tooltip shows identity signals (hostname, vendor, mac, etc.)

- **Smart-Check CPE Validation**: Enhanced Nuclei false positive detection using CPE data.
  - New functions: `parse_cpe_components()`, `validate_cpe_against_template()`, `extract_host_cpes()`
  - Cross-validates findings against host CPEs before HTTP header checks

- **PCAP Management**: New utilities for PCAP file organization.
  - `merge_pcap_files()`: Consolidates capture files using mergecap
  - `organize_pcap_files()`: Moves raw captures to subdirectory
  - `finalize_pcap_artifacts()`: Orchestrates post-scan cleanup

- **Docker/Deep Scan Optimization (H2)**:
  - **Nikto**: Extended timeouts (5m) and removed tuning constraints for deeper coverage.
  - **Nuclei**: Included "low" severity findings (e.g., info leaks) in the scan results.

### Changed

- **Risk Score Algorithm (V2)**: Refactored to fully integrate findings severity (low/med/high/crit) into the final score. Hosts with critical configuration flaws now accurately reflect High/Critical risk even without CVEs.
- **Warning Suppression**: Suppressed noisy ARP/Scapy warnings during L2 discovery for cleaner terminal output.
- **HTML Templates**: Both EN and ES templates updated with new columns and tooltips.

### Documentation

- Updated wizard profile descriptions with HyperScan mode selection.
- Added i18n translations (EN/ES) for HyperScan mode options.

## [4.2.1] - 2026-01-06

### Fixed

- Minor documentation and badge fixes.

## [4.2.0] - 2026-01-06

### Added

- **Parallel Deep Scan**: Decoupled Deep Scan phase running with full concurrency (up to 50 threads) and multi-bar UI.
- **Web App Scanning**: Integrated `sqlmap` (SQLi detection) and `OWASP ZAP` (spidering) into the vulnerability scan phase.
- **Multi-bar Progress**: Visual parallel progress bars for Deep Scan tasks.
- **i18n**: Complete Spanish translations for HyperScan and Deep Scan status messages.

### Changed

- **UI Polish**: Standardized checkmark emojis to ✅ across the CLI.
- **Deep Scan Config**: Removed artificial thread limits; now respects global `--threads` setting.

### Fixed

- **Duplicated Hosts**: Implemented aggressive IP sanitization (ANSI stripping) in `Auditor` to prevent "ghost" duplicate hosts in scan lists.
- **Progress Glitches**: Fixed issue where sequential HyperScan would sometimes report incorrect task counts.

## [4.1.0] - 2026-01-06

### Added

- **Sequential HyperScan-First Pre-scan**: New `_run_hyperscan_prescan()` method runs full port discovery (65,535 ports) sequentially on all hosts *before* parallel nmap fingerprinting. This eliminates file descriptor exhaustion and allows `batch_size=2000` for faster scanning.
- **Masscan Port Reuse**: When masscan has already discovered ports for a host, HyperScan-First reuses them instead of re-scanning.
- **Online OUI Vendor Lookup**: When local arp-scan/netdiscover return "Unknown" vendor, RedAudit now falls back to macvendors.com API for MAC vendor enrichment.
- **Basic sqlmap Integration**: Added `run_sqlmap()` to vulnerability scanning for automatic SQL injection detection on web targets. Runs in batch mode with forms crawl and smart scan.
- **sqlmap Auto-detection**: Added sqlmap to `TOOL_CONFIGS` for automatic version detection and reporting.

### Changed

- **Nmap Command Optimization**: Removed redundant `-sV -sC` flags when `-A` is used (since `-A` already includes them). Applied to both `auditor_scan.py` and `nmap.py`.
- **Parallel Vuln Tools**: Increased `ThreadPoolExecutor` workers from 3 to 4 to accommodate sqlmap alongside testssl, whatweb, and nikto.

### Fixed

- **Infinite Recursion Bug**: Fixed `hasattr(self, "_hyperscan_prescan_ports")` causing infinite recursion due to custom `__getattr__` in Auditor classes. Changed to `"_hyperscan_prescan_ports" in self.__dict__`.

### Documentation

- **v4.2 Roadmap**: Added planned features: Web App Vuln Scan (full sqlmap/ZAP), Deep Scan separation, Red Team → Agentless data pass, Wizard UX improvements, HyperScan naming cleanup, Session log enhancement.

### Installer

- **sqlmap**: Added to `EXTRA_PKGS` in `redaudit_install.sh` for automatic installation.

## [4.0.4] - 2026-01-05

### Fixed

- **Critical: HyperScan Port Integration**: When HyperScan detects open ports during net_discovery but the initial nmap scan found none (due to identity threshold), we now force a deep scan. This fixes the Metasploitable2 detection gap where 10+ ports were detected by HyperScan but ignored.
- **Vulnerability Detection Gap**: Hosts passing identity threshold but having HTTP fingerprints (from net_discovery/agentless probes) now correctly trigger web vulnerability scanning.
- **Port-based Web Detection**: Added `WEB_LIKELY_PORTS` constant (3000, 3001, 5000, 8000, 8080, 8443, 8888, 9000) as fallback for web service detection when nmap misidentifies services.
- **Vuln Scan Host Selection**: `scan_vulnerabilities_concurrent()` now includes hosts with `agentless_fingerprint.http_title` or `http_server` even when `web_ports_count=0`.
- **Agentless Summary Accuracy**: `_summarize_agentless()` now counts HTTP signals from `agentless_fingerprint` (http_title/http_server), not just from `agentless_probe`.
- **Descriptive Title Priority**: Improved `_derive_descriptive_title()` to use tiered priority — SSL/TLS issues (mismatch, expired) now rank above minor info leaks (ETag inode).
- **CLI Visual Regression**: Fixed colors not displaying correctly during progress UI. Changed from Rich markup strings to `rich.text.Text` objects for reliable styling.
- **Progress Bar Display**: Fixed progress bar showing raw `Host(ip='...')` object. Now displays clean IP string.
- **Spinner Restored**: Re-added `SpinnerColumn` to progress bar for visual feedback during long scans.
- **UIManager State Sync**: Added `progress_active_callback` to ensure consistent color output from all code paths.

### Changed

- **Deep Scan Logic**: Uses HyperScan ports as signal for deep scan decision (`hyperscan_ports_detected` reason). Also forces `web_count` when HyperScan found web ports (80, 443, 3000, 8080, etc.).
- **HyperScan Fallback**: When nmap times out (returncode 124) or finds 0 ports, we now populate the port list from HyperScan data with `hyperscan_fallback_used` flag. This handles slow-responding hosts like Metasploitable2.
- **Rich Colors**: Upgraded from `yellow`/`green`/`red` to `bright_yellow`/`bright_green`/`bright_red` for better visibility in dark terminal themes.

## [4.0.3] - 2026-01-05

### Added

- **Proxy routing**: Proxy settings now wrap external tools via proxychains (nmap, agentless probes,
  enrichment, vuln tools, nuclei) for TCP connect pivots.
- **Proxy lifecycle**: Added session status and cleanup to remove temporary proxychains configs.

### Changed

- **CommandRunner**: Added optional command wrapper support for proxy routing.
- **CLI**: `--proxy` now enforces proxychains availability and clarifies TCP-only behavior.

### Fixed

- **Proxy Support**: `--proxy` is now applied across scan/vuln/enrichment flows instead of being
  silently ignored.

### Documentation

- **Proxy scope**: Clarified proxychains requirement and TCP-only limitations in EN/ES docs.

### Tests

- **Coverage**: Added tests for proxy wrapper wiring and CLI proxychains gating.

## [4.0.2] - 2026-01-05

### Changed

- **Tests**: Reorganized the suite to mirror source layout (`tests/core`, `tests/cli`,
  `tests/utils`, `tests/integration`) and consolidated satellite files.
- **Coverage**: Expanded meaningful coverage for auditor components, vulnerability scanning,
  wizard flows, and hyperscan utilities.

### Fixed

- **CI**: Avoided global terminal size patching that could break pytest output in CI.

### Documentation

- **Process**: Clarified release/CI gating and ES documentation language guidance in `AGENTS.md`.

## [4.0.1] - 2026-01-04

### Changed

- **Architecture**: Main auditor now delegates component behavior through
  `redaudit/core/auditor_runtime.py`, keeping orchestration composition-first.
- **Testing**: Hardened OUI lookup import error test to avoid external requests and time-skew
  warnings.
- **Documentation**: Aligned composition refactor wording across roadmap and release notes.

### Removed

- **Tests**: Removed `tests/test_entity_resolver_extra.py` (coverage filler).

## [4.0.0] - 2026-01-04

### Added

- **Data Models**: New `Host`, `Service`, `Vulnerability` dataclasses in `redaudit/core/models.py`.
- **Composition**: `NetworkScanner` class replacing `AuditorScan`.
- **Architecture**: Full migration to object-based pipeline in `auditor_scan.py` and `reporter.py`.

### Changed

- **Refactor**: Replaced legacy inheritance-based scanning logic with composed scanner.
- **Reporting**: Updated `reporter.py` to serialize `Host` objects for JSON/HTML reports.
- **Testing**: Major cleanup of test suite, ensuring tests verify logic (48/48 core tests passing).

### Removed

- Legacy "coverage filler" tests.
- Deprecated inheritance logic related to ad-hoc dictionary handling.

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
