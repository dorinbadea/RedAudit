# RedAudit v3.9.5a — Installer & Tooling

[![Ver en Español](https://img.shields.io/badge/Español-blue?style=flat-square)](RELEASE_NOTES_v3.9.5a_ES.md)

**Release Date**: 2025-12-28

## Highlights

This release ensures comprehensive web vulnerability analysis tools are available out-of-the-box after installation, fixing reliability issues with the `testssl.sh` installation.

## Added

### Installer: Web Analysis Tools

Added `whatweb`, `nikto`, and `traceroute` to the apt package list in `redaudit_install.sh`:

```bash
EXTRA_PKGS="... whatweb nikto traceroute"
```

These tools enable deeper web vulnerability analysis in **completo** (full) scan mode:

- **whatweb**: Web technology fingerprinting
- **nikto**: Web server vulnerability scanner
- **traceroute**: Network path analysis for topology discovery

## Fixed

### Installer: testssl.sh Reliability

**Problem**: The previous installer used strict commit hash verification for `testssl.sh` that would fail if the upstream repository's tag structure changed.

**Solution**: Removed strict commit verification. Now uses version tag `v3.2` with automatic fallback to latest HEAD if the tag is unavailable:

```bash
# Try version tag first, fallback to latest
if git clone --depth 1 --branch "$TESTSSL_VERSION" "$TESTSSL_REPO" /opt/testssl.sh; then
    echo "[OK] Cloned testssl.sh $TESTSSL_VERSION"
elif git clone --depth 1 "$TESTSSL_REPO" /opt/testssl.sh; then
    echo "[OK] Cloned testssl.sh (latest)"
fi
```

### CI: test_fping_sweep_logic

Fixed the mock target in `tests/test_net_discovery_features.py` to properly simulate `fping` unavailability in GitHub Actions runner. Now mocks both `shutil.which` and `_run_cmd` instead of `CommandRunner`.

### Coverage Badge

Replaced broken dynamic Gist badge with static 84% coverage badge in README files.

## Upgrade Instructions

```bash
# For fresh installs
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.9.5a/redaudit_install.sh | sudo bash

# For existing installations, re-run the installer to get the new tools
sudo redaudit_install.sh
```

After installation, verify tools are detected:

```bash
redaudit --version
# Should show no warnings about missing tools
```

---

**Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
