# RedAudit v4.20.3 - Coverage Guardrails and Test Stabilization

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.3/docs/releases/RELEASE_NOTES_v4.20.3_ES.md)

## Summary

This patch release finalizes local recovery work, hardens coverage quality gates, and stabilizes authentication unit tests in large full-suite runs.

## Added

- Added changed-file coverage enforcement utilities:
  - `scripts/check_changed_coverage.py`
  - `redaudit/utils/coverage_gate.py`
- Added CI/local gate integration to enforce `>=98%` coverage for changed `redaudit/*.py` files.

## Improved

- Enhanced local CI parity flow in `scripts/ci_local.sh` to generate `coverage.json` and run changed-file coverage checks.
- Hardened SMB/SNMP unit-test determinism by reloading mocked modules explicitly to avoid import-order side effects.

## Fixed

- Preserved and validated `tests/core/test_auditor_run_complete_scan.py` in the active branch.
- Preserved `auditor_scan` compatibility behavior for mixed tag containers and legacy mDNS fixture formats.

## Testing

Internal validation completed.

## Upgrade

No action required.
