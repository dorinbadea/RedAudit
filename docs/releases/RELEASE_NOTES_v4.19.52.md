# RedAudit v4.19.52 - HTML Report Language Consistency

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.52/docs/releases/RELEASE_NOTES_v4.19.52_ES.md)

## Summary

This patch aligns HTML reporting with the selected run language and improves dashboard clarity when there is no chart data.

## Added

- No new end-user features in this release.

## Improved

- `report.html` now follows the active run language (`en` or `es`).
- Dashboard charts now show explicit no-data states instead of appearing broken.

## Fixed

- Spanish runs no longer produce an additional `report_es.html`; output is now a single `report.html` in the selected language.
- Profiles with no findings or no collected top-port distribution now render a clear no-data message.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
