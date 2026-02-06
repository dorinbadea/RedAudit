[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.16/docs/releases/RELEASE_NOTES_v4.6.16_ES.md)

# RedAudit v4.6.16 - Nuclei Timeout Hardening

## Summary

- Reduces Nuclei partial runs with adaptive batch timeouts and recursive splits.
- Uses per-request timeout/retries when supported by the installed Nuclei version.

## Added

- None.

## Improved

- Nuclei retries and timeout handling now degrade batch size automatically to isolate slow targets.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
