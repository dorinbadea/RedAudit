# RedAudit v4.18.21 - Home Copy Refresh Safety

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.21/docs/releases/RELEASE_NOTES_v4.18.21_ES.md)

## Summary

System updates now preserve local changes in `~/RedAudit` by backing up the folder and refreshing the home copy, keeping documentation current.

## Added

- None.

## Improved

- System updates back up dirty `~/RedAudit` folders and refresh the home copy instead of skipping updates.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v --cov=redaudit --cov-report=term-missing`

## Upgrade

No breaking changes. Update to v4.18.21.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.21/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.21/docs/INDEX.md)
