# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

- **SIEM-Compatible Output (A5)**: Enhanced JSON reports for Splunk/Elastic integration
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
  - Runs in all scan modes (fast/normal/completo)
  - New function: `exploit_lookup()` in `redaudit/core/scanner.py`

- **TestSSL.sh Integration**: Comprehensive SSL/TLS security analysis for HTTPS services
  - Deep SSL/TLS vulnerability scanning (Heartbleed, POODLE, BEAST, etc.)
  - Weak cipher and protocol detection
  - Only runs in `completo` mode (60-second timeout per port)
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

## [2.5.0] - 2025-12-07 (Adaptive Deep Scan)

### Added

- **Adaptive Deep Scan (v2.5)**: Implemented a smart 2-phase strategy (Aggressive TCP first -> UDP+OS fallback). to maximize speed and data.
- **Vendor/MAC Detection**: Native regex parsing to extract hardware vendor from Nmap output.
- **Installer**: Refactored `redaudit_install.sh` to specific clean copy operations without embedded Python code.

### Changed

- **Heartbeat**: Professional messaging ("Nmap is still running") to reduce user anxiety during long scans.
- **Reporting**: Added `vendor` and `mac_address` fields to JSON/TXT reports.

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
