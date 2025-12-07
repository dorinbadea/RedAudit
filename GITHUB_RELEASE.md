# RedAudit v2.5.0 - Security Hardening & Automation

## 🚀 Major Release: Security Hardening & Non-Interactive Mode

RedAudit v2.5.0 introduces **enterprise-grade security improvements** and **full automation support** for professional security workflows.

### 🔒 Security Enhancements

- **Hardened Input Sanitization**
  - Type validation (only `str` accepted)
  - Length limits to prevent DoS (1024 chars for IPs, 50 for CIDR)
  - Automatic whitespace stripping
  - Comprehensive validation before any command execution

- **Secure File Permissions**
  - All reports now use `0o600` permissions (owner read/write only)
  - Applies to JSON, TXT, encrypted files, and salt files

- **Improved Cryptography Handling**
  - Graceful degradation if `python3-cryptography` unavailable
  - Clear warnings in English and Spanish
  - No password prompts if encryption unavailable

### 🤖 Non-Interactive Mode (NEW!)

Full CLI support for automation, scripting, and CI/CD integration:

```bash
# Basic scan
sudo redaudit --target 192.168.1.0/24 --mode normal

# Full scan with encryption
sudo redaudit --target 10.0.0.0/24 --mode full --threads 8 --encrypt --output /tmp/reports

# Multiple targets
sudo redaudit --target "192.168.1.0/24,10.0.0.0/24" --mode normal

# Automation (skip legal warning)
sudo redaudit --target 192.168.1.0/24 --mode fast --yes
```

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

