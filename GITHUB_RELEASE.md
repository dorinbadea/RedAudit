# RedAudit v3.0.1

## Patch Release - Configuration Management

### v3.0.1 Highlights

- **Persistent NVD API Key Storage**: Secure configuration file (`~/.redaudit/config.json`) for NVD API keys.
- **Interactive Setup Prompts**: Guided configuration for CVE correlation during installation and first run.
- **Environment Variable Support**: `NVD_API_KEY` environment variable integration.
- **Documentation Perfection**: Complete synchronization across all 25+ documentation files.

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
```

### Testing & Quality

- **Tests**: 86 automated tests passing
- **Coverage**: ~89%
- **Security**: CodeQL & Dependabot active
- **License**: GPLv3

### Documentation

Complete bilingual documentation (English/Spanish):

- [README.md](README.md) / [README_ES.md](README_ES.md)
- [MANUAL_EN.md](docs/MANUAL_EN.md) / [MANUAL_ES.md](docs/MANUAL_ES.md)
- [USAGE.md](docs/USAGE.md) / [USAGE_ES.md](docs/USAGE_ES.md)

### Links

- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Release Notes**: [RELEASE_NOTES_v3.0.0.md](RELEASE_NOTES_v3.0.0.md)
- **Security Specs**: [docs/SECURITY.md](docs/SECURITY.md)
