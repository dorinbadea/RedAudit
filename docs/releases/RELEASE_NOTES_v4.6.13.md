[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.13/docs/releases/RELEASE_NOTES_v4.6.13_ES.md)

# RedAudit v4.6.13 - Target Summary and Scan Feedback

## Summary

- Adds clearer pre-run target scope visibility and improves scan feedback during long-running phases.

## Added

- Wizard target normalization summary with estimated host counts.

## Improved

- Nuclei progress tracks target-level movement inside batches.
- Nikto timeouts surface in vulnerability progress details.

## Fixed

- Media devices with Chromecast services no longer default to router classification.
- OWASP Juice Shop titles resolve to server-class assets.
- `run_manifest.json` partial now reflects Nuclei timeout batches.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
