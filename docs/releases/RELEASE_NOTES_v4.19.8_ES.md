# RedAudit v4.19.8 - Integridad de artefactos de reanudacion

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/docs/releases/RELEASE_NOTES_v4.19.8.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/docs/releases/RELEASE_NOTES_v4.19.8_ES.md)

## Summary

Los artefactos de reanudacion mantienen coherencia entre resumenes, objetivos y exportaciones JSONL, y los objetivos Nuclei se conservan.

## Added

- Ninguno.

## Improved

- El progreso de reanudacion de Nuclei refleja el total de objetivos con contexto de reanudacion.

## Fixed

- Los resumenes de reanudacion cuentan hosts desde resultados existentes y preservan redes objetivo.
- La reanudacion de Nuclei ya no sobrescribe `nuclei_targets.txt`; los pendientes quedan en `nuclei_pending.txt`.
- Las exportaciones JSONL agregan activos minimos para hosts con hallazgos, manteniendo `asset_id` completo.
- Los logs de sesion mantienen el color INFO al respetar el estado TTY del terminal.
- Los avisos de identidad profunda omiten sufijos de version heredados.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.8.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/docs/INDEX.md)
