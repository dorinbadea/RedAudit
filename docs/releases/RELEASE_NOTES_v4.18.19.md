# RedAudit v4.18.19 - UI Consistency and Snapshot Coverage

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.19/docs/releases/RELEASE_NOTES_v4.18.19_ES.md)

## Summary

This release aligns UI language handling, improves progress styling, and expands report config snapshots for better audit traceability.

## Added

- None.

## Improved

- Rich progress output applies the status color to all message lines for consistent contrast.
- Report config snapshots now include `deep_id_scan`, `trust_hyperscan`, and `nuclei_timeout`.

## Fixed

- UI language changes now update the UI manager to prevent mixed EN/ES output.
- WARN signal filtering recognizes Spanish keywords during progress rendering.
- Dependency checks, auth failures, and scan errors now use localized strings.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v --cov=redaudit --cov-report=term-missing`

## Upgrade

No breaking changes. Update to v4.18.19.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.19/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.19/docs/INDEX.md)
