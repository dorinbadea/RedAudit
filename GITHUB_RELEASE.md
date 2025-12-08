# RedAudit v2.5.0

## Hardening & Automation Release

### Features
- **Security**: Reinforced input sanitization pipeline with strict allowlisting.
- **Permissions**: Enforced `0o600` permissions on all report artifacts.
- **Automation**: Complete CLI argument support for headless execution.

### Installation
```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

**SHA256 Checksums:**
- `redaudit.py`: [Pending Build]
- `redaudit_install.sh`: [Pending Build]

**Available Options:**
- `--target, -t`: Target network(s) in CIDR notation
- `--mode, -m`: fast/normal/full (default: normal)
- `--threads, -j`: 1-16 (default: 6)
- `--rate-limit`: Delay between hosts in seconds
- `--encrypt, -e`: Encrypt reports
- `--output, -o`: Output directory
- `--max-hosts`: Limit number of hosts
- `--yes, -y`: Skip legal warning
- `--lang`: Language (en/es)

### 🧪 Testing

- **Integration Tests**: Comprehensive test suite
- **Encryption Tests**: Full coverage for encryption functionality
- All tests passing ✅

### 📚 Documentation

Complete documentation updates in English and Spanish:
- README.md / README_ES.md
- Professional Manuals (MANUAL_EN.md / MANUAL_ES.md)
- Usage Guides (USAGE.md / USAGE_ES.md)
- Security Documentation (SECURITY.md)
- Troubleshooting Guide (TROUBLESHOOTING.md)
- Report Schema (REPORT_SCHEMA.md)

### 🐛 Bug Fixes

- Fixed missing `_combined_output_has_identity()` function
- Fixed cryptography availability check flow
- Fixed sanitizer type validation issues

### 📦 Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
source ~/.bashrc  # or ~/.zshrc
```

### 🔗 Links

- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Documentation**: [docs/](docs/)
- **Security Specs**: [docs/SECURITY.md](docs/SECURITY.md)
- **License**: GPLv3

---

**Note**: This release maintains backward compatibility. No breaking changes.

