# Security Architecture & Hardening

RedAudit v2.3 is built with a "Secure by Design" philosophy, assuming execution in hostile or untrusted environments.

## 1. Input Sanitization & Safety
All external inputs—target ranges, hostnames, interface names—are treated as untrusted.
- **Strict Allowlisting**: We use strict regex patterns (`^[a-zA-Z0-9\.\-\/]+$`) for IPs and interfaces.
- **Library Validation**: Python’s `ipaddress` library confirms CIDR/IP validity before any shell command sees them.
- **Command Construction**: No user input is directly concatenated into shell strings without validation.

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

## 4. Audit Trails
- **Logging**: Rotating logs stored in `~/.redaudit/logs/` (max 10MB, 5 backups).
- **Traceability**: Every scan logs the user (`SUDO_USER`), PID, and start time.
