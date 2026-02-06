# RedAudit v4.18.15 - Almacen de pistas de hostname

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.15/docs/releases/RELEASE_NOTES_v4.18.15.md)

## Summary

Esta version externaliza las pistas basadas en hostname al almacen de firmas para mantener configurable la clasificacion de identidad y activos.

## Added

- Ninguno.

## Improved

- Las pistas basadas en hostname ahora cargan desde el archivo de firmas para identidad y clasificacion de activos.

## Fixed

- Ninguno.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.15 para pistas de hostname data-driven.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.15/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.15/docs/INDEX.md)
