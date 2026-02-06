# RedAudit v4.19.5 - Metadatos de reanudacion de Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/docs/releases/RELEASE_NOTES_v4.19.5.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/docs/releases/RELEASE_NOTES_v4.19.5_ES.md)

## Summary

Los informes de reanudacion ahora preservan redes objetivo y duracion total tras reanudar Nuclei.

## Added

- None.

## Improved

- El contexto de reanudacion restaura redes objetivo faltantes para informes consistentes.

## Fixed

- El resumen ya no reinicia la duracion a 0:00:00 tras completar objetivos pendientes de Nuclei.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.5.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/docs/INDEX.md)
