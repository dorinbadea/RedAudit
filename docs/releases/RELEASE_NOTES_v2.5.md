# RedAudit Release Notes - v2.5.0

**Release Date**: 2025-12-07
**Version**: 2.5.0

## Summary
This release focuses on security hardening of the runtime environment and full support for non-interactive automation workflows.

### Security Enhancements
- **Input Sanitization**: Implemented strict type and regex validation for all user inputs.
- **File Permissions**: Output artifacts now default to `0o600` (user-only read/write).
- **Cryptography**: Added graceful degradation logic when cryptographic libraries are missing.

### Automation
- **Non-Interactive Mode**: Fully scriptable execution via CLI arguments (`--target`, `--mode`, `--encrypt`).
- **Bypass**: Added `--yes` flag to bypass legal disclaimers in automated pipelines.

### Usage
```bash
sudo redaudit --target 192.168.1.0/24 --mode full --encrypt
````--lang`
- All interactive options available via CLI

### Testing
- **Integration Tests**: Comprehensive test suite (`test_integration.py`)
- **Encryption Tests**: Full coverage for encryption functionality (`test_encryption.py`)
- All existing tests updated and passing

## Changes

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

## Installation

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
source ~/.bashrc  # or ~/.zshrc
```

## Documentation

All documentation has been updated:
- README.md / README_ES.md
- MANUAL_EN.md / MANUAL_ES.md
- USAGE.en.md / USAGE_ES.md
- SECURITY.en.md
- TROUBLESHOOTING.en.md
- REPORT_SCHEMA.en.md
- CHANGELOG.md

## Bug Fixes

- Fixed missing `_combined_output_has_identity()` function
- Fixed cryptography availability check flow
- Fixed sanitizer type validation issues

## Breaking Changes

None. This is a backward-compatible release.

## Credits

Thanks to all contributors and users who provided feedback!

---

**Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
**Documentation**: [docs/](docs/)
**License**: GPLv3
