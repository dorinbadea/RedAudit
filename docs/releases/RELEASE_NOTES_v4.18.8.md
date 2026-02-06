# RedAudit v4.18.8 - Installer Toolchain Pinning

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.8/docs/releases/RELEASE_NOTES_v4.18.8_ES.md)

## Summary

This release adds a toolchain pinning mode to the installer, introduces a Poetry lockfile for evaluation, and refactors Red Team discovery into a dedicated module.

## Added

- None.

## Improved

- Installer supports `REDAUDIT_TOOLCHAIN_MODE=latest` for testssl/kerbrute plus explicit version overrides (`TESTSSL_VERSION`, `KERBRUTE_VERSION`, `RUSTSCAN_VERSION`).
- Added `poetry.lock` alongside pip-tools for workflow parity and evaluation.
- Red Team discovery logic now lives in a dedicated module to reduce `net_discovery.py` size.

## Fixed

- Kerbrute installer no longer reports "already installed" after a fresh install.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.8 to control toolchain versions during install.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.8/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.8/docs/INDEX.md)
