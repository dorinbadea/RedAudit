# RedAudit v3.0.0

## Smart Improvements, UDP Taming & Entity Resolution

### Highlights

- **Smart-Check**: Intelligent false positive filtering for Nikto (90% noise reduction).
- **UDP Taming**: Optimized 3-phase UDP scanning strategy (50-80% faster).
- **Entity Resolution**: Intelligent grouping of multi-interface devices into unified assets.
- **SIEM Professional**: Enhanced JSON schema compliant with ECS v8.11 for usage in Splunk/Elastic.
- **Clean Documentation**: Complete overhaul of documentation for clarity and consistency.

### New Features

- **Smart-Check**: Analyzes Content-Type to suppress irrelevant findings (e.g., Nikto flagging JSON endpoints).
- **Unified Assets**: Correlates IPs by MAC address to show physical device count.
- **Risk Scoring**: Dynamic 0-100 risk score per host based on vulnerabilities and open services.
- **Strict UDP**: New defaults (`--top-ports 100`, `--host-timeout 300s`) prevent scan hangs.
- **Clean Docs**: Removed confusing historical version tags from all Manuals/READMEs.

### Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### CLI Options

- `--target, -t`: Target network(s) in CIDR notation
- `--mode, -m`: fast/normal/full (default: normal)
- `--threads, -j`: 1-16 (default: 6)
- `--rate-limit`: Delay between hosts in seconds (supports jitter)
- `--encrypt, -e`: Encrypt reports (Strong password required)
- `--udp-mode`: UDP scan mode (quick/full)
- `--prescan`: Enable fast asyncio pre-scan
- `--lang`: Language (en/es)

### Package Structure

```text
redaudit/
├── core/
│   ├── auditor.py       # Orchestrator
│   ├── entity_resolver.py # [NEW] Asset unification
│   ├── verify_vuln.py   # [NEW] Smart filter
│   ├── siem.py          # [NEW] SIEM integration
│   ├── prescan.py       # Asyncio discovery
│   └── ...
└── utils/
```

### Testing & Quality

- **Tests**: 86 automated tests passing
- **Coverage**: ~89%
- **Security**: CodeQL & Dependabot active
- **License**: GPLv3

### Documentation

Complete bilingual documentation (English/Spanish), now fully standardized:

- [README.md](README.md) / [README_ES.md](README_ES.md)
- [MANUAL_EN.md](docs/MANUAL_EN.md) / [MANUAL_ES.md](docs/MANUAL_ES.md)
- [USAGE.md](docs/USAGE.md) / [USAGE_ES.md](docs/USAGE_ES.md)

### Links

- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Release Notes**: [RELEASE_NOTES_v3.0.0.md](RELEASE_NOTES_v3.0.0.md)
- **Security Specs**: [docs/SECURITY.md](docs/SECURITY.md)
