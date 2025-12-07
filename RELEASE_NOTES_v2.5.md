# RedAudit v2.5.0 Release Notes

**Release Date**: December 7, 2025  
**Tag**: `v2.5.0`

## 🎉 What's New

### 🔒 Security Hardening
- **Hardened Input Sanitization**: All inputs now validated for type, length, and format
  - Type validation (only `str` accepted)
  - Length limits (1024 chars for IPs/hostnames, 50 for CIDR)
  - Automatic whitespace stripping
- **Secure File Permissions**: All reports use 0o600 permissions (owner read/write only)
- **Improved Cryptography Handling**: Graceful degradation if `python3-cryptography` unavailable

### 🤖 Non-Interactive Mode (NEW!)
Full CLI support for automation and scripting:
```bash
sudo redaudit --target 192.168.1.0/24 --mode full --threads 8 --encrypt
```

**Key Features:**
- Complete argument parsing with `argparse`
- Support for multiple targets (comma-separated)
- `--yes` flag for automated runs (skips legal warning)
- Language selection via `--lang`
- All interactive options available via CLI

### 🧪 Testing
- **Integration Tests**: Comprehensive test suite (`test_integration.py`)
- **Encryption Tests**: Full coverage for encryption functionality (`test_encryption.py`)
- All existing tests updated and passing

## 📝 Changes

### Added
- Non-interactive CLI mode with full argument support
- Input length validation (MAX_INPUT_LENGTH, MAX_CIDR_LENGTH constants)
- Secure file permissions (0o600) for all reports
- Integration and encryption test suites
- Graceful cryptography degradation with clear warnings

### Changed
- Sanitizers now validate type, strip whitespace, and enforce length limits
- `check_dependencies()` verifies cryptography availability
- `setup_encryption()` doesn't prompt if cryptography unavailable
- Version updated to 2.5.0
- Deep scan strategy updated to "adaptive_v2.5"

### Security
- All user inputs validated for type and length
- File permissions hardened
- Better exception handling prevents information leakage

## 🔧 Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
source ~/.bashrc  # or ~/.zshrc
```

## 📚 Documentation

All documentation has been updated:
- README.md / README_ES.md
- MANUAL_EN.md / MANUAL_ES.md
- USAGE.md / USAGE_ES.md
- SECURITY.md
- TROUBLESHOOTING.md
- REPORT_SCHEMA.md
- CHANGELOG.md

## 🐛 Bug Fixes

- Fixed missing `_combined_output_has_identity()` function
- Fixed cryptography availability check flow
- Fixed sanitizer type validation issues

## ⚠️ Breaking Changes

None. This is a backward-compatible release.

## 🙏 Credits

Thanks to all contributors and users who provided feedback!

---

**Full Changelog**: [CHANGELOG.md](CHANGELOG.md)  
**Documentation**: [docs/](docs/)  
**License**: GPLv3

