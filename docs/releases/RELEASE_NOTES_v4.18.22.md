# RedAudit v4.18.22 - Nuclei Timeout Coverage Floor

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.22/docs/releases/RELEASE_NOTES_v4.18.22_ES.md)

## Summary

RedAudit now keeps the configured Nuclei batch timeout as a floor on split retries, preserving coverage on slow HTTP targets.

## Added

- None.

## Improved

- Nuclei split retries keep the configured timeout floor to avoid coverage loss during exhaustive scans.

## Fixed

- Nuclei split retries no longer reduce timeouts below the configured batch timeout, reducing partial runs on slow targets.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.22.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.22/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.22/docs/INDEX.md)
