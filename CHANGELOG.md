# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [2.5.0] - 2025-05-21 (Adaptive Deep Scan)

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
