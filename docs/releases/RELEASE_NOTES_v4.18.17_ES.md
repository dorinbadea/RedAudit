# RedAudit v4.18.17 - Alineacion de HyperScan y visibilidad UDP

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.17/docs/releases/RELEASE_NOTES_v4.18.17.md)

## Summary

Esta version alinea el resumen de HyperScan-First con el CLI y expone el total de UDP en los resumenes del pipeline y en los informes HTML.

## Added

- El resumen del pipeline ahora incluye el total de puertos UDP detectados por HyperScan.
- Los informes HTML muestran el conteo de puertos UDP de HyperScan.

## Improved

- La documentacion del esquema de reportes incluye el campo del conteo UDP de HyperScan.

## Fixed

- Las comparativas de HyperScan-First ahora usan solo TCP para coincidir con el CLI.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.17 para el resumen alineado y la visibilidad UDP.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.17/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.17/docs/INDEX.md)
