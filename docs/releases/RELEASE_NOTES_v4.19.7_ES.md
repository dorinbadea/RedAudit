# RedAudit v4.19.7 - Exclusion de autoobjetivo Red Team

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/docs/releases/RELEASE_NOTES_v4.19.7.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/docs/releases/RELEASE_NOTES_v4.19.7_ES.md)

## Summary

El descubrimiento Red Team ahora excluye las IPs del auditor al seleccionar objetivos para evitar auto-enumeracion.

## Added

- None.

## Improved

- None.

## Fixed

- La seleccion de objetivos Red Team omite las IPs del auditor antes de iniciar la enumeracion.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.7.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/docs/INDEX.md)
