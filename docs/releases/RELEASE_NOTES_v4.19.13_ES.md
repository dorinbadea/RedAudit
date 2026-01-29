# RedAudit v4.19.13 - Estabilidad Python del instalador

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/docs/releases/RELEASE_NOTES_v4.19.13.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/docs/releases/RELEASE_NOTES_v4.19.13_ES.md)

## Summary

El instalador evita conflictos de pip instalando solo modulos faltantes y agrega fallback de archivo para exploitdb/searchsploit.

## Added

- Sin cambios.

## Improved

- Se incluyen instalaciones apt opcionales de python3-paramiko y python3-keyrings-alt.

## Fixed

- Las instalaciones pip se limitan a modulos faltantes para evitar conflictos con paquetes gestionados por el sistema.
- exploitdb/searchsploit puede instalarse desde un archivo de GitHub si falla el git clone.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.13.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/docs/INDEX.md)
