# Security Architecture & Hardening

## Overview
RedAudit implements a "secure by design" philosophy, assuming execution in hostile or untrusted environments. This document outlines the security controls regarding input handling, cryptography, and operational safety.

## 1. Input Sanitization
All external inputs—target ranges, hostnames, interface names—are treated as untrusted and subjected to strict validation.
- **Strict Typing**: Only `str` types accepted for critical parameters.
- **Regex Allowlisting**: IPs and hostnames must match strict patterns (`^[a-zA-Z0-9\.\-\/]+$`).
- **Command Injection Prevention**: `subprocess.run` is used exclusively with argument lists; shell expansion (`shell=True`) is disabled.

## 2. Cryptographic Implementation
Report encryption is handled via the `cryptography` library to ensure confidentiality of audit results.
- **Primitive**: AES-128-CBC (Fernet specification).
- **Key Management**: Keys are derived from user-supplied passwords using PBKDF2HMAC-SHA256 with 480,000 iterations and a per-session random salt.
- **Integrity**: Fernet includes a HMAC signature to prevent ciphertext tampering.

## 3. Operational Security (OpSec)
- **Artifact Permissions**: RedAudit enforces `0o600` (read/write by owner only) on all generated reports to prevent information leakage to other users on the system.
- **Evasion**: Configurable rate limiting suppresses network noise to evade threshold-based intrusion detection systems (IDS).
- **Heartbeat**: Background monitoring ensures process integrity without requiring interactive shell access.

## 4. Audit Trail
All operations are logged to `~/.redaudit/logs/` with rotation policies (max 10MB, 5 backups). Logs contain execution timestamps, thread identifiers, and raw command invocations for accountability.

## 5. License

This security model is part of the RedAudit project and is covered by the  
**GNU General Public License v3.0 (GPLv3)**. See [LICENSE](../LICENSE) for the full text.
