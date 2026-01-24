# RedAudit v4.18.14 - Exclusion del auditor y almacen de firmas

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.14/docs/releases/RELEASE_NOTES_v4.18.14.md)

## Summary

Esta version anade un almacen de firmas basado en datos para pistas de vendors y templates FP de Nuclei, y refuerza la exclusion del auditor con fallbacks best-effort.

## Added

- Archivos de datos para pistas de vendors y expectativas de templates FP de Nuclei.

## Improved

- Ninguno.

## Fixed

- La exclusion de IPs del auditor ahora hace fallback a deteccion local cuando faltan network_info y topologia.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.14 para mayor seguridad de exclusion del auditor y mantenimiento de firmas mas sencillo.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.14/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.14/docs/INDEX.md)
