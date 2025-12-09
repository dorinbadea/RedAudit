# RedAudit v2.6.1

## Security Hardening, Exploit Intelligence & UX Polish

### Highlights

- **Exploit Intelligence**: Integrated `searchsploit` for automatic exploit lookup based on service versions.
- **SSL/TLS Auditing**: Integrated `testssl.sh` for deep cryptographic analysis of HTTPS services.
- **Security Hardening**: Enforced strong passwords (12+ chars, mixed case, numbers) for encryption.
- **Enhanced UX**: Added `rich` progress bars with graceful fallback.
- **CI/CD Security**: Added Dependabot and CodeQL for automated security scanning.

### New Features

- **Progress Bars**: New visual feedback for concurrent scanning.
- **Tool Activation Matrix**: Clear documentation on when external tools are triggered.
- **SearchSploit**: Automatically queries ExploitDB for detected services.
- **TestSSL**: Deep SSL/TLS analysis in `full` mode.
- **Architecture Diagrams**: Added Mermaid diagrams to READMEs.

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
- `--rate-limit`: Delay between hosts in seconds
- `--encrypt, -e`: Encrypt reports (Strong password required)
- `--output, -o`: Output directory
- `--lang`: Language (en/es)

### Package Structure

```text
redaudit/
├── core/           # Core functionality
│   ├── auditor.py  # Main orchestrator
│   ├── crypto.py   # Encryption (PBKDF2, Fernet)
│   ├── network.py  # Network detection
│   ├── reporter.py # Report generation
│   └── scanner.py  # Scanning logic (SearchSploit, TestSSL)
└── utils/          # Utilities
    ├── constants.py
    └── i18n.py
```

### Testing & Quality

- **Tests**: 34 automated tests passing
- **Coverage**: ~60% threshold enforced in CI
- **Security**: CodeQL & Dependabot active

### Documentation

Complete bilingual documentation (English/Spanish):

- README.md / README_ES.md
- MANUAL_EN.md / MANUAL_ES.md (Restructured & Professionalized)
- USAGE.md / USAGE_ES.md
- SECURITY.md, TROUBLESHOOTING.md, REPORT_SCHEMA.md

### Backward Compatibility

- Original `redaudit.py` preserved as wrapper
- All existing scripts continue to work

### Links

- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Documentation**: [docs/](docs/)
- **Security Specs**: [docs/SECURITY.md](docs/SECURITY.md)
- **License**: GPLv3
