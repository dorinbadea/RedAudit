# Release Notes v3.4.0 - Playbook Export

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.4.0_ES.md)

**Release Date**: 2025-12-17

## Overview

RedAudit v3.4.0 introduces **Remediation Playbooks** - automatically generated Markdown guides that provide actionable steps to remediate detected vulnerabilities.

## New Features

### Remediation Playbook Generation

After each scan, RedAudit now generates remediation playbooks in the `<output_dir>/playbooks/` directory. Each playbook contains:

- **Step-by-step remediation instructions**
- **Suggested shell commands** for common fixes
- **Reference links** to OWASP, Mozilla, NVD, and CIS

#### Playbook Categories

| Category | Triggers |
| :--- | :--- |
| **TLS Hardening** | Weak ciphers, outdated TLS versions, certificate issues |
| **HTTP Headers** | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| **CVE Remediation** | Known CVEs detected via NVD correlation |
| **Web Hardening** | Directory listing, server banners, default pages (Nikto findings) |
| **Port Hardening** | Dangerous services: Telnet, FTP, SMBv1, SNMP with public community |

#### Example Output

```
~/Documents/RedAuditReports/2025-12-17/playbooks/
├── 192_168_1_1_tls_hardening.md
├── 192_168_1_1_http_headers.md
├── 192_168_1_5_cve_remediation.md
└── 192_168_1_10_port_hardening.md
```

## Technical Details

- **New module**: `redaudit/core/playbook_generator.py`
- **Integration**: Playbooks generated automatically via `reporter.py` after scan completion
- **12 unit tests** added for playbook generator

## Upgrade Instructions

```bash
# If installed via GitHub
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh

# Or fresh install
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/main/redaudit_install.sh | sudo bash
```

---

*RedAudit v3.4.0 - Making vulnerability remediation actionable.*
