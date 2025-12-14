# RedAudit v3.1

## Feature Release - SIEM & AI Pipeline Enhancements

### v3.1 Highlights

- **JSONL Exports**: Auto-generated `findings.jsonl`, `assets.jsonl`, and `summary.json` for SIEM/AI pipelines.
- **Finding IDs**: Deterministic hashes for finding deduplication across scans.
- **Category Classification**: Findings categorized as surface/misconfig/crypto/auth/info-leak/vuln.
- **Normalized Severity**: CVSS-like 0-10 scale with preserved original tool severity.
- **Parsed Observations**: Structured extraction from Nikto/TestSSL raw output.
- **Scanner Versions**: Provenance tracking with detected tool versions.

### v3.0 Major Features

- **IPv6 Support**: Full scanning capabilities for IPv6 networks with automatic `-6` flag.
- **CVE Correlation (NVD)**: Deep vulnerability intelligence via NIST NVD API with 7-day cache.
- **Differential Analysis**: Compare two JSON reports to track network changes over time.
- **Proxy Chains (SOCKS5)**: Network pivoting support via proxychains wrapper.
- **Magic Byte Validation**: Enhanced false positive detection with file signature verification.

### Previous (v2.9) Features

- **Smart-Check**: Intelligent false positive filtering for Nikto (90% noise reduction).
- **UDP Taming**: Optimized 3-phase UDP scanning strategy (50-80% faster).
- **Entity Resolution**: Intelligent grouping of multi-interface devices into unified assets.
- **SIEM Professional**: Enhanced JSON schema compliant with ECS v8.11.

---

### Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### New in v3.1 - JSON Output

```json
{
  "schema_version": "3.1",
  "scanner_versions": {"redaudit": "3.1.0", "nmap": "7.95"},
  "finding_id": "12273fca7e8dbe0e...",
  "category": "misconfig",
  "normalized_severity": 7.0,
  "parsed_observations": ["Missing X-Frame-Options header"]
}
```

### New Modules (v3.1)

```text
redaudit/core/
├── scanner_versions.py  # Tool version detection
├── evidence_parser.py   # Nikto/TestSSL parsing
└── jsonl_exporter.py    # JSONL/JSON export views
```

### CLI Options

| Flag | Description |
|:---|:---|
| `--ipv6` | Enable IPv6-only scanning mode |
| `--proxy URL` | SOCKS5 proxy for pivoting |
| `--diff OLD NEW` | Compare two JSON reports |
| `--cve-lookup` | Enable CVE correlation via NVD API |
| `--nvd-key KEY` | NVD API key for faster rate limits |
| `--allow-non-root` | Run in limited mode without sudo/root |

### Testing & Quality

- **Tests**: ![Tests](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg)
- **Coverage**: Reported by CI (see Actions/Codecov)
- **Security**: CodeQL & Dependabot active
- **License**: GPLv3

### Documentation

Complete bilingual documentation (English/Spanish):

- [README.md](README.md) / [README_ES.md](README_ES.md)
- [MANUAL_EN.md](docs/MANUAL_EN.md) / [MANUAL_ES.md](docs/MANUAL_ES.md)
- [USAGE.md](docs/USAGE.md) / [USAGE_ES.md](docs/USAGE_ES.md)

### Links

- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Release Notes**: [RELEASE_NOTES_v3.1.md](RELEASE_NOTES_v3.1.md)
- **Security Specs**: [docs/SECURITY.md](docs/SECURITY.md)
