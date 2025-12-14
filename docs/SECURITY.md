# Security Architecture & Hardening

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](SECURITY_ES.md)

## Security Policy

### Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in RedAudit, please report it responsibly:

1. **Email**: Send details to `security@dorinbadea.com`
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
3. **Response Time**: You will receive an acknowledgment within 48 hours
4. **Disclosure**: We follow responsible disclosure - we will coordinate with you on public disclosure timing

### Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 3.0.x   | Yes                | Current stable |
| 2.9.x   | Security fixes only | EOL: March 2026 |
| 2.8.x   | No                 | EOL |
| < 2.8   | No                 | EOL |

---

## Security Architecture

### Overview

RedAudit implements a "secure by design" philosophy, assuming execution in hostile or untrusted environments. This document outlines the security controls regarding input handling, cryptography, and operational safety.

## 1. Input Sanitization

All external inputs—target ranges, hostnames, interface names—are treated as untrusted and subjected to strict validation.

- **Strict Typing**: Only `str` types accepted for critical parameters.
- **IP Address Validation**: Uses Python's `ipaddress` module to validate both IPv4 and IPv6 addresses. Invalid IPs return `None`.
- **Hostname Validation**: Regex allowlisting (`^[a-zA-Z0-9\.\-]+$`) ensures only alphanumeric characters, dots, and hyphens.
- **Length Limits**: All inputs are truncated to `MAX_INPUT_LENGTH` (1024 chars) to prevent buffer-based attacks.
- **Command Injection Prevention**: `subprocess.run` is used exclusively with argument lists; shell expansion (`shell=True`) is disabled.
- **Module Location**: `redaudit/core/scanner.py` (`sanitize_ip`, `sanitize_hostname`)

## 2. Cryptographic Implementation

Report encryption is handled via the `cryptography` library to ensure confidentiality of audit results.

- **Primitive**: AES-128-CBC (Fernet specification).
- **Key Management**: Keys are derived from user-supplied passwords using PBKDF2HMAC-SHA256 with 480,000 iterations and a per-session random salt.
- **Integrity**: Fernet includes a HMAC signature to prevent ciphertext tampering.
- **Password Policy**: Minimum 12 characters with complexity requirements (uppercase, lowercase, digit).
- **Module Location**: `redaudit/core/crypto.py`

## 3. Operational Security (OpSec)

- **Artifact Permissions**: RedAudit enforces `0o600` (read/write by owner only) on all generated reports to prevent information leakage to other users on the system.
- **Jitter Rate-Limiting**: Configurable rate limiting with ±30% random variance to evade threshold-based IDS and behavioral analysis.
- **Pre-scan Discretion**: Asyncio-based port discovery minimizes nmap invocations, reducing overall network footprint.
- **Heartbeat**: Background monitoring ensures process integrity without requiring interactive shell access.
- **Module Location**: `redaudit/core/reporter.py` (file permissions), `redaudit/core/auditor.py` (heartbeat, jitter), `redaudit/core/prescan.py` (fast discovery)

## 4. Audit Trail

All operations are logged to `~/.redaudit/logs/` with rotation policies (max 10MB, 5 backups). Logs contain execution timestamps, thread identifiers, and raw command invocations for accountability.

## 5. CI/CD Security

Automated security controls are integrated into the development pipeline:

- **Bandit**: Static security linting for Python code on every push/PR
- **Dependabot**: Weekly scans for vulnerable dependencies (pip, GitHub Actions)
- **CodeQL**: Static analysis for security vulnerabilities on every push/PR
- **Multi-version Testing**: Compatibility verified across Python 3.9-3.12

## 6. Modular Architecture

The codebase is organized into focused modules to improve maintainability and auditability:

- **Core modules** (`redaudit/core/`): Security-critical functionality
- **Utilities** (`redaudit/utils/`): Constants and internationalization
- **Tests**: Automated test suite runs in GitHub Actions (`.github/workflows/tests.yml`) across Python 3.9–3.12; the exact test count is tracked by CI rather than hard-coded in docs.

## 7. Secure Auto-Update

RedAudit includes a secure update mechanism that checks GitHub for new releases:

- **No arbitrary downloads**: Uses `git clone` from the official repository
- **Pinned to tags**: Update flow resolves the published tag and verifies the commit hash before installing
- **Integrity verification**: Git's built-in hash verification ensures authenticity
- **User confirmation**: Always prompts before applying updates
- **Network failure handling**: Graceful degradation if GitHub is unavailable
- **Local changes protection**: Refuses to update if uncommitted changes exist
- **Module location**: `redaudit/core/updater.py`

## 8. NVD API Key Storage (v3.0.1+)

RedAudit supports storing NVD API keys for CVE correlation:

- **Config File**: `~/.redaudit/config.json` with `0600` permissions
- **Environment Variable**: `NVD_API_KEY` (never logged)
- **Priority**: CLI flag → Environment → Config file
- **No plaintext in logs**: API keys are never written to log files
- **Atomic writes**: Config updates use temp file + rename for crash safety

Users should treat the config file as sensitive. The API key grants increased rate limits but does not provide access to private data.

## 9. Known Limitations

- **Requires root/sudo**: Necessary for raw socket access (nmap, tcpdump)
- **No sandboxing**: External tools run with full system privileges
- **Network visibility**: Scans generate significant network traffic

Users should only run RedAudit in authorized, controlled environments.

## 10. License

This security model is part of the RedAudit project and is covered by the  
**GNU General Public License v3.0 (GPLv3)**. See [LICENSE](../LICENSE) for the full text.
