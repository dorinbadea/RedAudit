# Security Architecture & Hardening
The security of **RedAudit v2.5** is a priority. This document describes the security policies, architecture, and philosophy, assuming execution in hostile or untrusted environments.

## 1. Input Sanitization & Safety (Enhanced in v2.5)
All external inputs—target ranges, hostnames, interface names—are treated as untrusted.
- **Type Validation**: All sanitizers now validate input type (only `str` accepted), preventing type confusion attacks.
- **Length Limits**: Maximum input lengths enforced (1024 chars for IPs/hostnames, 50 for CIDR) to prevent DoS.
- **Automatic Stripping**: All inputs are automatically stripped of leading/trailing whitespace.
- **Strict Allowlisting**: We use strict regex patterns (`^[a-zA-Z0-9\.\-\/]+$`) for IPs and interfaces.
- **Library Validation**: Python's `ipaddress` library confirms CIDR/IP validity before any shell command sees them.
- **Command Construction**: No user input is directly concatenated into shell strings without validation. All commands use `subprocess.run` with argument lists.

## 2. Encryption Standard
RedAudit uses the industrial-strength **Fernet** specification for report encryption.
- **Algorithm**: AES-128 in CBC mode.
- **Authentication**: HMAC-SHA256 (preventing tampering).
- **Key Derivation**: PBKDF2HMAC-SHA256.
    - **Iterations**: 480,000 (exceeds OWASP recommendations).
    - **Salt**: 16-byte random salt per scan, stored in `.salt` files.

## 3. Operational Security (OpSec)
- **Rate Limiting**: Configurable delays (0-60s) between tests to evade simple heuristic detection.
- **Traffic Capture Cap**: `tcpdump` captures are strictly capped at 50 packets or 15 seconds to prevent disk fills or process hangs.
- **Activity Monitor**: Background heartbeat thread ensures the process doesn't "zombie" silently.
- **Deep Scan Privacy**: Automated traffic captures (Deep Scan) are stored locally. These **PCAP files may contain sensitive payload data** (e.g., cleartext HTTP/Telnet). RedAudit never transmits these files; they are strictly for the operator's analysis.
- **Secure File Permissions** (v2.5): All generated reports (JSON, TXT, encrypted, salt files) use 0o600 permissions (owner read/write only), preventing unauthorized access.
- **Graceful Cryptography Handling** (v2.5): If `python3-cryptography` is unavailable, encryption is automatically disabled with clear warnings. No password prompts are shown, preventing user confusion and failed operations.

## 4. Audit Trails
- **Logging**: Rotating logs stored in `~/.redaudit/logs/` (max 10MB, 5 backups).
- **Traceability**: Every scan logs the user (`SUDO_USER`), PID, and start time.

## 5. License

This security model is part of the RedAudit project and is covered by the  
**GNU General Public License v3.0 (GPLv3)**. See [LICENSE](../LICENSE) for the full text.
