[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.5/docs/releases/RELEASE_NOTES_v4.6.5_ES.md)

## Summary

Hardens the update flow so version reporting stays accurate even when tags or local installs are inconsistent. The updater now forces the target `VERSION`, avoids partial system updates without sudo, and the runtime banner prefers the packaged version file.

## Added

- None.

## Improved

- Update flow now blocks non-root system updates when running `/usr/local/bin/redaudit` to prevent partial installs.

## Fixed

- Updater forces the packaged `VERSION` file to match the target tag during updates.
- Version resolution now prefers the packaged `VERSION` file over installed metadata to avoid stale banners.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

```bash
git pull origin main
```
