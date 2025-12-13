# RedAudit v3.0.1 - Release Notes

**Release Date**: December 13, 2025  
**Type**: Patch Release - Configuration Management  
**Previous Version**: v3.0.0

---

## Overview

Version 3.0.1 is a focused patch release that enhances the NVD CVE correlation feature introduced in v3.0.0 by adding persistent API key configuration, interactive setup wizards, and comprehensive documentation synchronization.

This release is fully backward compatible with v3.0.0 and requires no migration steps for existing users.

---

## What's New in v3.0.1

### 1. Persistent NVD API Key Storage

**New Module**: `redaudit/utils/config.py`

RedAudit now stores configuration persistently in `~/.redaudit/config.json`, eliminating the need to pass `--nvd-key` on every execution.

**Key Features**:

- Secure file permissions (`0o600` for config file, `0o700` for directory)
- Automatic creation on first use
- Version tracking (`CONFIG_VERSION = "3.0.1"`)
- JSON-based format for easy editing

**Configuration File Location**:

```bash
~/.redaudit/config.json
```

**Configuration Priority** (highest to lowest):

1. CLI argument: `--nvd-key KEY` (session only, not persisted)
2. Environment variable: `NVD_API_KEY`
3. Configuration file: `~/.redaudit/config.json`

> **Note**: The `--nvd-key` flag is for one-time use and is not saved. To persist your key, use the environment variable or config file methods.

**Security Notes**:

- Config file is created with `0o600` permissions (read/write for owner only)
- Config directory is created with `0o700` permissions
- API keys are never logged in plain text
- See [SECURITY.md](docs/SECURITY.md#8-nvd-api-key-storage-v301) for full security specification

---

### 2. Interactive Setup Prompts

**Installation-Time Setup** (`redaudit_install.sh`):

The installer includes an optional prompt for NVD API key configuration:

```bash
Enter your API key (or ENTER to skip):
```

If provided, the key is saved to `~/.redaudit/config.json` with secure permissions.

**First-Run Setup** (`redaudit/core/auditor.py`):

When CVE correlation is enabled (`--cve-lookup`) and no API key is configured, RedAudit prompts interactively with more options:

- **Config File**: Store permanently in `~/.redaudit/config.json`
- **Environment Variable**: Instructions to add to shell profile
- **Skip**: Continue without API key (slower rate limits)

---

### 3. Environment Variable Support

RedAudit now reads the `NVD_API_KEY` environment variable automatically:

```bash
# One-time usage
export NVD_API_KEY="your-api-key-uuid"
sudo -E redaudit --target 192.168.1.0/24 --cve-lookup

# Persistent (add to ~/.bashrc or ~/.zshrc)
echo 'export NVD_API_KEY="your-api-key-uuid"' >> ~/.bashrc
source ~/.bashrc
```

**Note**: The `-E` flag preserves environment variables when using `sudo`.

---

### 4. Enhanced Internationalization

**New Translation Strings** (18 total):

English (`redaudit/utils/i18n.py`):

- `nvd_setup_prompt`
- `nvd_setup_options`
- `nvd_key_input`
- `nvd_key_invalid`
- `nvd_key_saved_config`
- `nvd_key_saved_env`
- `nvd_setup_skipped`
- `cve_lookup_q`
- ... and 10 more

Spanish equivalents for all strings ensure full bilingual support.

---

### 5. Documentation Perfection

All 25+ documentation files synchronized to v3.0.1:

**Version References Updated**:

- ✅ `README.md` / `README_ES.md`: Version badge `3.0.1`
- ✅ `MANUAL_EN.md` / `MANUAL_ES.md`: Header `v3.0.1`
- ✅ `DIDACTIC_GUIDE.md` / `GUIA_DIDACTICA.md`: Version `v3.0.1` + TL;DR sections
- ✅ `GITHUB_RELEASE.md`: New v3.0.1 section
- ✅ `CHANGELOG.md`: Dedicated `[3.0.1]` entry

**New Documentation Sections**:

- `USAGE.md` / `USAGE_ES.md`: "CVE Correlation Setup" section
- `SECURITY.md` / `SECURITY_ES.md`: "NVD API Key Storage (v3.0.1)" section
- `CONTRIBUTING.md` / `CONTRIBUTING_ES.md`: Updated package structure with `config.py`

**Didactic Guide Enhancements**:

- Added **TL;DR for Instructors** at the beginning
- Quick reference for 60-minute lectures
- Practical exercises clearly marked (Section 8)

---

## Technical Details

### Modified Files

**Core Code**:

- `redaudit/utils/config.py` (NEW)
- `redaudit/core/nvd.py` (MODIFIED)
- `redaudit/core/auditor.py` (MODIFIED)
- `redaudit/utils/i18n.py` (MODIFIED)
- `redaudit/utils/constants.py` (MODIFIED - VERSION = "3.0.1")

**Installation Scripts**:

- `redaudit_install.sh` (MODIFIED)

**Documentation** (16 files updated):

- Core: `README.md`, `README_ES.md`, `CHANGELOG.md`, `GITHUB_RELEASE.md`
- Manuals: `MANUAL_EN.md`, `MANUAL_ES.md`
- Guides: `DIDACTIC_GUIDE.md`, `GUIA_DIDACTICA.md`
- Usage: `USAGE.md`, `USAGE_ES.md`
- Security: `SECURITY.md`, `SECURITY_ES.md`
- Contributing: `CONTRIBUTING.md`, `CONTRIBUTING_ES.md`
- Release: `RELEASE_NOTES_v3.0.1.md` (THIS FILE)

---

## Upgrade Guide

### From v3.0.0 to v3.0.1

**Automatic Upgrade** (Recommended):

If you installed via `redaudit_install.sh`:

```bash
cd RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

The installer will detect the upgrade and preserve your configuration.

**Manual Upgrade**:

```bash
cd RedAudit
git pull origin main
# No additional steps required - fully backward compatible
```

**Configuration Migration**: Not required. If you were using `--nvd-key` in v3.0.0, you can now optionally migrate to persistent config:

```bash
sudo redaudit --cve-lookup
# You will be prompted to save your API key
```

---

## Breaking Changes

**None**. Version 3.0.1 is fully backward compatible with 3.0.0.

Existing workflows using `--nvd-key KEY` will continue to work without modification.

---

## Known Issues

None specific to v3.0.1.

For general troubleshooting, see [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## Contributors

- **Dorin Badea** (@dorinbadea) - Lead Developer

---

## Links

- **GitHub Release**: [v3.0.1](https://github.com/dorinbadea/RedAudit/releases/tag/v3.0.1)
- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Previous Release**: [RELEASE_NOTES_v3.0.0.md](RELEASE_NOTES_v3.0.0.md)
- **Installation Guide**: [README.md#installation](README.md#installation)
- **Security Policy**: [docs/SECURITY.md](docs/SECURITY.md)

---

## What's Next?

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for our roadmap and planned features for v3.1.0 and beyond.

**Stay Updated**:

- ⭐ Star the repository
- 👁️ Watch for releases
- 🐛 Report issues on GitHub

---

**Thank you for using RedAudit!**
