# Release Notes v4.5.3

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.3/docs/releases/RELEASE_NOTES_v4.5.3_ES.md)

**Release Date:** 2026-01-10

## Summary

This release adds secure credential storage via OS keychain and fixes scan audit bugs identified during Docker lab testing.

## Added

- **Secure Credential Storage (Keyring)**: `keyring` package now included as core dependency for secure credential storage.
  - Uses native OS keychain: Linux Secret Service, macOS Keychain, Windows Credential Vault.
  - Added to main dependencies (`pyproject.toml`) and installer (`python3-keyring` apt + pip).
  - No credentials stored in plain text.

## Fixed

- **B2 - Vuln Progress Bars**: Progress bars now always reach 100% after scan completion. Added final loop to ensure all tasks update correctly.

- **B3 - Heartbeat INFO Color**: Changed heartbeat message from grey50 to cyan for proper visibility during long scans.

- **B4 - SSH Detection Failure**: Fixed "No SSH-enabled hosts found for authenticated scanning" false negative. The `has_ssh_port()` function now correctly handles `Host` Pydantic objects (not just dicts).

## Testing

- 18 keyring-specific tests passing
- Full pre-commit validation
- All credential provider flows tested

## Upgrade

```bash
cd ~/RedAudit && git pull && sudo bash redaudit_install.sh
```

The installer now automatically installs `python3-keyring` (apt) and `keyring` (pip) for secure credential storage.
