# Security Architecture & Hardening

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](../es/SECURITY.md)

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
| 3.4.x   | Yes                | Current stable |
| 3.3.x   | Yes                | Supported |
| 3.2.x   | Security fixes only | Maintenance |
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

- **Artifact Permissions**: RedAudit enforces `0o600` (read/write by owner only) on generated artifacts (reports, HTML/playbooks, JSONL export views, externalized evidence) to reduce leakage to other users on the same system.
- **Encrypted Mode Safety**: When report encryption is enabled, RedAudit avoids generating additional plaintext artifacts (HTML/JSONL/playbooks/summary and externalized evidence) alongside `.enc` reports.
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

## 7. Reliable Auto-Update

RedAudit includes an update mechanism that checks GitHub for new releases:

- **No arbitrary downloads**: Uses `git clone` from the official repository
- **Pinned to tags**: Update flow resolves the published tag and verifies the commit hash before installing
- **Integrity verification**: Git's built-in hash verification ensures data has not been corrupted in transit
- **User confirmation**: Always prompts before applying updates
- **Network failure handling**: Graceful degradation if GitHub is unavailable
- **Local changes protection**: Refuses to update if uncommitted changes exist
- **Staged installation**: New files are copied to a staging directory before atomically replacing the current installation (v3.2.3+)
- **Rollback on failure**: If installation fails, the previous version is restored automatically (v3.2.3+)
- **Module location**: `redaudit/core/updater.py`

> [!IMPORTANT]
> **Security Limitation**: The update system verifies that cloned commits match expected git refs (integrity) but does **NOT** perform cryptographic signature verification of tags or releases (authenticity). If GitHub or the repository is compromised, malicious code could be distributed. Users requiring higher assurance should verify releases manually or implement GPG signature verification.

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
- **Optional recon features**: `--net-discovery` / `--redteam` may invoke additional broadcast/L2 tooling (best-effort; use only with explicit authorization)

Users should only run RedAudit in authorized, controlled environments.

## 11. Red Team & Active Recon Safety

RedAudit v3.2 introduces **Active Reconnaissance** capabilities (`--redteam`, `--net-discovery`) that differ from standard scanning:

- **Broadcasting**: These modes send L2 broadcast/multicast packets (ARP, mDNS, NetBIOS).
- **Probing**: Active interaction with services (SNMP, SMB, Kerberos) occurs if detected.
- **Traceability**: Unlike passive listening, these actions **will generate logs** on target systems and may trigger IDS/IPS rules.
- **Authorization**: Ensure you have explicit permission for **active** internal discovery, not just external vulnerability scanning.

### Tool-Specific Warnings

| Tool | Capability | Risk Level | Authorization Required |
|:-----|:-----------|:-----------|:-----------------------|
| `snmpwalk` | Queries SNMP agents for network device information (VLANs, ARP tables, interface configs) | **Medium** - Logs on SNMP-enabled devices | ✅ Internal admin approval |
| `enum4linux` | Enumerates Windows SMB shares, users, password policies, domain info | **High** - Triggers security logs, may alert SOC | ✅ Domain admin approval |
| `masscan` | Ultra-fast port scanner (1M packets/sec capability) | **High** - High network noise, likely IDS trigger | ✅ Network team + security approval |
| `rpcclient` | Windows RPC enumeration (users, groups, shares) | **High** - Active Directory logs, auth attempts | ✅ Domain admin approval |
| `ldapsearch` | LDAP/AD queries for organizational structure | **Medium** - LDAP server logs queries | ✅ Directory admin approval |
| `bettercap` | Multi-purpose L2 attack framework (ARP spoofing, MITM, injection) | **Critical** - Active network attacks, illegal without authorization | ✅ Executive + legal approval |
| `scapy` (passive) | Passive packet sniffing for 802.1Q VLAN tags | **Low** - Passive only (no injection) | ⚠️ Requires promiscuous mode (root) |
| `kerbrute` | Kerberos user enumeration via pre-auth checks | **High** - Generates Failed Logons (Event 4771) on DC | ✅ Domain admin approval |
| `proxychains4` | Routes traffic through SOCKS5 proxies | **Medium** - Evades network controls / firewall logging | ✅ Network security approval |

### Best Practices for Red Team Features

1. **Document Authorization**: Obtain written approval before using `--redteam` flags
2. **Limit Scope**: Use `--redteam-max-targets` to constrain the number of probed hosts
3. **Avoid Production Hours**: Schedule active recon during maintenance windows
4. **Monitor Impact**: Watch for network congestion or service degradation
5. **Disable bettercap**: Unless absolutely necessary, avoid `--redteam-active-l2` (enables potentially destructive L2 attacks)

## 12. HTML Dashboard & Webhook Security (v3.3+)

### HTML Reports (`--html-report`)

- **Offline/Air-gap Safe**: The generated HTML reports are fully self-contained. All CSS (Bootstrap) and JS (Chart.js) logic is embedded directly into the file. No external requests are made when opening the report, making it safe for air-gapped analysis stations.
- **No Remote Tracking**: No analytics or tracking pixels are included.

### Webhook Alerts (`--webhook`)

- **Sensitive Data Transmission**: This feature sends finding details (Target IP, Vulnerability Title, Severity) to the configured URL.
- **HTTPS Required**: Always use `https://` webhook URLs to protect this data in transit.
- **Verification**: Ensure the webhook URL is correct and trusted (e.g., your internal Slack/Teams instance) to avoid leaking vulnerability data to third parties.

## 13. License

This security model is part of the RedAudit project and is covered by the
**GNU General Public License v3.0 (GPLv3)**. See [LICENSE](../../LICENSE) for the full text.
