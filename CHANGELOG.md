# Changelog

All notable changes to this project will be documented in this file.

## [v2.3] - 2025-12-06

### Added
- **Heartbeat Monitor**: A new background thread monitors Nmap activity to detect freezes and report progress periodically.
- **Deep Scan Automation**: Automatically triggers aggressive scans (`-A -sV -Pn` + UDP) and traffic capture for unresponsive or "suspiciously quiet" hosts.
- **Traffic Capture**: Integration with `tcpdump` and `tshark` to capture traffic snippets for analysis (if tools are available).
- **Output Directory**: Default output directory set to `~/RedAuditReports`.
- **Installer Improvements**: Added check for `apt` and root privileges. Added `-y` flag for non-interactive installation.

### Changed
- **Dependency Management**: Python core no longer installs dependencies. All dependency checks are done at startup with clear "Required" vs "Recommended" distinction.
- **Web Scanning**: `whatweb` and `nikto` are now recommended (optional) rather than hard requirements.
- **Reporting**: Improved JSON and TXT report structure.
- **Error Handling**: Better concurrency management in worker threads; individual host failures do not crash the entire audit.

### Fixed
- Fixed concurrency crashes by adding try/except blocks in thread futures.
- Resolved installer issues on non-Kali Debian systems by strictly checking for `apt`.

## [v2.2] - Previous Release
- Initial stable release with multi-threading and basic report generation.
