# RedAudit v4.18.18 - Wizard Contrast and Low-Impact Enrichment

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.18/docs/releases/RELEASE_NOTES_v4.18.18_ES.md)

## Summary

This release adds an opt-in HTTP/HTTPS probe for vendor-only hosts with zero open ports, improves wizard contrast, and clamps Nuclei split timeouts to avoid long stalls.

## Added

- Phase 0 low-impact enrichment now supports a short HTTP/HTTPS probe for vendor-only hosts with zero open ports.

## Improved

- Wizard menus render non-selected options in blue and highlight default values in prompts.
- Nuclei split retries now clamp timeouts to reduce long waits on slow targets.

## Fixed

- Smart scan summaries now respect `low_impact_enrichment` when the configuration is a `ConfigurationContext`.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.18 for clearer wizard prompts and safer enrichment and Nuclei retries.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.18/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.18/docs/INDEX.md)
