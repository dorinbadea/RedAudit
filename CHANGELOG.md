# Changelog
All notable changes to this project will be documented in this file.
RedAudit is licensed under GPLv3. See LICENSE for details.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2025-05-21 (Deep Identity Engine)

### Added
- **Deep Identity Scan**: New logic to automatically fingerprint complex hosts using combined `nmap -O -sV -p- -sSU` scans.
- **Micro-Traffic Capture**: Heuristic-based `tcpdump` captures (50 packets) for active identification of silent services.
- **Reporting**: Extended JSON report schema with specific `deep_scan` command logs, durations, and pcap paths.
- **CLI UX**: Added clear markers `[nmap]` and `[deep]` to show exact scan phases in real-time.

### Changed
- **Heartbeat**: Improved warnings to clarify that long silences during deep scans are normal ("Nmap is still running").
- **Triggers**: Expanded automatic deep scan triggers to include specific service names (vpn, proxy, nagios) and high port counts (>8).



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
