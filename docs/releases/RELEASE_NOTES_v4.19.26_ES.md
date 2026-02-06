# RedAudit v4.19.26 - Compatibilidad bash del seed del keyring

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.26/docs/releases/RELEASE_NOTES_v4.19.26.md)

## Summary

Garantiza que el script de seed del keyring funcione correctamente incluso al invocarlo con `bash`.

## Added

- None.

## Improved

- None.

## Fixed

- `scripts/seed_keyring.py` ahora redirige a Python cuando se lanza con `bash`.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.26.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.26/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.26/docs/INDEX.md)
