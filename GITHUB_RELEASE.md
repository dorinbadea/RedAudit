# RedAudit v3.0.3

## Patch Release - Update UX & Language Preservation

### v3.0.3 Highlights

- **Language Preserved on Update**: Auto-update keeps the installed language (e.g., Spanish stays Spanish).
- **More Explicit Auto-Update Output**: Shows target ref/commit, file changes (+/~/-), and explicit install/backup steps.

### v3.0 Major Features

- **IPv6 Support**: Full scanning capabilities for IPv6 networks with automatic `-6` flag.
- **CVE Correlation (NVD)**: Deep vulnerability intelligence via NIST NVD API with 7-day cache.
- **Differential Analysis**: Compare two JSON reports to track network changes over time.
- **Proxy Chains (SOCKS5)**: Network pivoting support via proxychains wrapper.
- **Magic Byte Validation**: Enhanced false positive detection with file signature verification.
- **Enhanced Auto-Update**: Git clone approach with verification and home folder copy.

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

### New CLI Options (v3.0)

| Flag | Description |
|:---|:---|
| `--ipv6` | Enable IPv6-only scanning mode |
| `--proxy URL` | SOCKS5 proxy for pivoting |
| `--diff OLD NEW` | Compare two JSON reports |
| `--cve-lookup` | Enable CVE correlation via NVD API |
| `--nvd-key KEY` | NVD API key for faster rate limits |
| `--allow-non-root` | Run in limited mode without sudo/root |

### Core CLI Options

- `--target, -t`: Target network(s) in CIDR notation
- `--mode, -m`: fast/normal/full (default: normal)
- `--threads, -j`: 1-16 (default: 6)
- `--rate-limit`: Delay between hosts in seconds
- `--encrypt, -e`: Encrypt reports
- `--udp-mode`: UDP scan mode (quick/full)
- `--prescan`: Enable fast asyncio pre-scan
- `--lang`: Language (en/es)

### New Modules (v3.0)

```text
redaudit/core/
├── nvd.py          # CVE correlation via NVD API
├── diff.py         # Differential analysis engine
└── proxy.py        # SOCKS5 proxy manager

redaudit/utils/
└── config.py       # Persistent configuration (v3.0.1+)
```

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
- **Release Notes**: [RELEASE_NOTES_v3.0.3.md](RELEASE_NOTES_v3.0.3.md)
- **Security Specs**: [docs/SECURITY.md](docs/SECURITY.md)
