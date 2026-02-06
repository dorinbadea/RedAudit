# RedAudit v4.5.0 - Authenticated Scanning & Red Team Toolkit

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v4.5.0_ES.md)

This release completes **Phase 4**, introducing comprehensive Authenticated Scanning capabilities and advanced Red Team modules. RedAudit can now dive deeper into hosts using valid credentials to uncover internal misconfigurations, vulnerabilities, and hardening gaps.

## New Features

### Authenticated Scanning (Phase 4)

RedAudit now supports deep credentialed audits across three major protocols:

- **SSH (Linux/Unix)**:
  - Retrieves exact Kernel versions, OS distribution, and uptime.
  - Enumerates installed packages (DEB/RPM).
  - **Lynis Integration**: Automates remote Lynis audits for CIS/Hardening scoring.
- **SMB/WMI (Windows)**:
  - Enumerates OS version, Domain/Workgroup, Shares, and Users.
  - Checks password policies and Guest access.
  - Requires `impacket` (optional dependency).
- **SNMP v3**:
  - Full support for crypto-agile SNMPv3 (Auth: MD5/SHA, Priv: DES/AES).
  - Extracts routing tables, interfaces, and system descriptions.

### Red Team Modules

- **Wizard Integration**: A new interactive flow guides users through configuring authentication and Red Team options.
- **Keyring Support**: Credentials can be securely stored in the system keyring, avoiding plaintext passwords in scripts.

## Improvements

- **Interactive Wizard**: Completely redesigned Wizard flow (Step 1-9) with "Go Back" functionality and new Authentication menus.
- **Documentation**: Comprehensive updates to `MANUAL.md` and `USAGE.md` detailing authenticated workflows.
- **Stability**: Fixed recursion errors in `AuditorRuntime` and improved test mock sequences.

## Fixes

- Resolved `StopIteration` crashes in interactive wizard tests.
- Fixed type checking errors (Mypy) in auth modules.
- Corrected circular dependency in `AuditorRuntime`.

## Upgrading

```bash
cd RedAudit
git pull origin main
# Install new dependencies (impacket, pysnmp)
pip install -r requirements.txt
```
