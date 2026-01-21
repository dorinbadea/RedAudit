# RedAudit v4.18.4 - Report Traceability and Discovery Transparency

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.4/docs/releases/RELEASE_NOTES_v4.18.4_ES.md)

## Summary

This release improves audit traceability in reports and surfaces discovery errors for transparency.

## Added

- None.

## Improved

- Nuclei suspected items are now listed in HTML/TXT for review.

## Fixed

- Net Discovery errors now appear in HTML/TXT pipeline sections.
- Config snapshots now persist `nuclei_profile` and `nuclei_full_coverage` in summary outputs.
- DHCP discovery now defaults to the default-route interface, probes all IPv4 interfaces in full mode, and reports timeouts as no-response.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- No special steps. Update and run as usual.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.4/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.4/docs/INDEX.md)
