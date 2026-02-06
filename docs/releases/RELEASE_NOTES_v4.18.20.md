# RedAudit v4.18.20 - Nuclei Resilience and UI Sync Refinement

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.20/docs/releases/RELEASE_NOTES_v4.18.20_ES.md)

## Summary

This release stabilizes long Nuclei runs, keeps UI language consistent after CLI overrides, and improves ANSI status contrast.

## Added

- None.

## Improved

- ANSI status lines now apply the status color to the full message text for consistent contrast outside Rich.

## Fixed

- UI manager now re-syncs language when the CLI language changes after initialization to prevent mixed EN/ES output.
- Long Nuclei timeouts now clamp parallel batches to reduce full-scan timeouts.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v --cov=redaudit --cov-report=term-missing`

## Upgrade

No breaking changes. Update to v4.18.20.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.20/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.20/docs/INDEX.md)
