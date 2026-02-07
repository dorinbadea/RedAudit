# RedAudit v4.19.49 - Python 3.10+ Baseline and Dependency Security Alignment

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.49/docs/releases/RELEASE_NOTES_v4.19.49_ES.md)

## Summary

This patch release aligns RedAudit with a modern, supported Python runtime baseline and removes residual dependency-alert noise tied to end-of-life Python 3.9.

## Added

- No new end-user features in this release.

## Improved

- Official runtime and CI baseline now targets Python 3.10-3.12.
- Project metadata, local CI parity tooling, and contributor guidance are aligned to the same Python baseline.

## Fixed

- Dependency lockfiles no longer include the Python 3.9-only `filelock` branch.
- `cryptography` minimum floor remains hardened and consistent with current secure versions in lockfiles.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
