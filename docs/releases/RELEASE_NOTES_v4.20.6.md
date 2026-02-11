# RedAudit v4.20.6 - Cryptography Security Remediation

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.6/docs/releases/RELEASE_NOTES_v4.20.6_ES.md)

## Summary

This patch release remediates an upstream cryptography vulnerability by upgrading lockfiles to the patched version.

## Added

- No new runtime features were added in this release.

## Improved

- Dependency lock consistency between production and development environments.

## Fixed

- Upgraded `cryptography` to `46.0.5` in:
  - `poetry.lock`
  - `requirements.lock`
  - `requirements-dev.lock`
- This resolves the published security issue affecting versions `<=46.0.4`.

## Testing

Internal validation completed.

## Upgrade

No action required.
