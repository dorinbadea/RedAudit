[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.7/docs/releases/RELEASE_NOTES_v4.6.7_ES.md)

## Summary

Prevents auth credential lookups during port scans when authentication is disabled and reduces session log noise from repeated progress redraws.

## Added

- None.

## Improved

- Session logs now deduplicate rich progress-bar redraws to reduce noise.

## Fixed

- Auth credential lookups are skipped during port scans when authentication is disabled, avoiding keyring stalls.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

```bash
git pull origin main
```
