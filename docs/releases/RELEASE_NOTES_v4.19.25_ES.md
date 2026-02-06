# RedAudit v4.19.25 - Limpieza de BetterCAP

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.25/docs/releases/RELEASE_NOTES_v4.19.25.md)

## Summary

Asegura la terminacion de BetterCAP tras la recon L2 para evitar procesos activos.

## Added

- None.

## Improved

- None.

## Fixed

- BetterCAP ahora se detiene de forma best-effort tras la recon para evitar que quede en ejecucion.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.25.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.25/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.25/docs/INDEX.md)
