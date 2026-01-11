[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.6/docs/releases/RELEASE_NOTES_v4.6.6_ES.md)

## Summary

Adds the "Trust HyperScan" prompt to the Exhaustive profile with a safe default of No.

## Added

- None.

## Improved

- Wizard now asks "Trust HyperScan" in the Exhaustive profile (default: No).

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

```bash
git pull origin main
```
