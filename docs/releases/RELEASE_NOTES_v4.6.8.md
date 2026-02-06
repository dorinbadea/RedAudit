[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.8/docs/releases/RELEASE_NOTES_v4.6.8_ES.md)

## Summary

Stabilizes vulnerability progress bars after host completion and ensures web assets are tagged when web ports are detected.

## Added

- None.

## Improved

- None.

## Fixed

- Vulnerability progress bars no longer update after a host finishes.
- Web assets now get the `web` tag when `web_ports_count` is present.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

```bash
git pull origin main
```
