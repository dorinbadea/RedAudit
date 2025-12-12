# Security Architecture & Hardening

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](SECURITY_ES.md)

## Overview

RedAudit implements a "secure by design" philosophy, assuming execution in hostile or untrusted environments. This document outlines the security controls regarding input handling, cryptography, and operational safety.

## 1. Input Sanitization

All external inputs—target ranges, hostnames, interface names—are treated as untrusted and subjected to strict validation.

- **Strict Typing**: Only `str` types accepted for critical parameters.
- **Regex Allowlisting**: IPs and hostnames must match strict patterns (`^[a-zA-Z0-9\.\-\/]+$`).
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
- **Test coverage**: 34 automated tests with CI/CD pipeline

## 7. Secure Auto-Update

RedAudit includes a secure update mechanism that checks GitHub for new releases:

- **No arbitrary downloads**: Uses `git pull` from the official repository
- **Integrity verification**: Git's built-in hash verification ensures authenticity
- **User confirmation**: Always prompts before applying updates
- **Network failure handling**: Graceful degradation if GitHub is unavailable
- **Local changes protection**: Refuses to update if uncommitted changes exist
- **Module location**: `redaudit/core/updater.py`

## 8. License

This security model is part of the RedAudit project and is covered by the  
**GNU General Public License v3.0 (GPLv3)**. See [LICENSE](../LICENSE) for the full text.
