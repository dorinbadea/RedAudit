[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.9/docs/releases/RELEASE_NOTES_v4.6.9_ES.md)

# RedAudit v4.6.9 - Identity-Aware Gating and Nuclei Partial Reporting

## Summary

This release reduces scan time on infrastructure devices without losing evidence by using identity signals (HTTP title/server and device type) to gate deep scans and heavy web app tools. It also adds partial Nuclei reporting when batch timeouts occur.

## Added

- Shared infrastructure identity helper used across web app gating and Nuclei false-positive checks.
- Nuclei summary fields for partial runs: `partial`, `timeout_batches`, `failed_batches`.
- Quick HTTP identity probe on quiet hosts to resolve identity earlier.

## Improved

- Deep scan decision considers HTTP title/server and device-type evidence to avoid unnecessary escalation.
- Web app scanning (sqlmap/ZAP) is skipped on infrastructure UIs when identity indicates router/switch/AP devices.
- Documentation updated across README, manuals, usage, troubleshooting, security, and report schema.

## Fixed

- Nuclei timeouts are now surfaced as partial runs instead of silent gaps.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `git pull origin main`
- `sudo bash redaudit_install.sh`
- Reopen your terminal to refresh the installed version
