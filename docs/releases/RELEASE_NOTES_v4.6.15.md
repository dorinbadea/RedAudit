[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.15/docs/releases/RELEASE_NOTES_v4.6.15_ES.md)

# RedAudit v4.6.15 - Nuclei Progress Stability and Report Consistency

## Summary

- Stabilizes Nuclei progress so target counts never regress during retries or timeouts.
- Aligns host entries with unified asset identity data for consistent reporting.

## Added

- None.

## Improved

- Nuclei progress now uses target counts and stays monotonic across batch retries/timeouts.

## Fixed

- Host report entries now include `asset_name`, `interfaces`, and `interface_count` when unified assets are present.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
