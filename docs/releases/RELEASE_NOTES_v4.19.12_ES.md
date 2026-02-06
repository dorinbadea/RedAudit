# RedAudit v4.19.12 - Dependencias Python del instalador

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/docs/releases/RELEASE_NOTES_v4.19.12.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/docs/releases/RELEASE_NOTES_v4.19.12_ES.md)

## Summary

El instalador asegura pip y prueba Impacket via apt para reducir dependencias Python faltantes en instalaciones limpias de Ubuntu.

## Added

- Sin cambios.

## Improved

- El toolchain del instalador incluye `python3-pip` para asegurar la instalacion de dependencias via pip.

## Fixed

- Las instalaciones limpias de Ubuntu ya no omiten dependencias de autenticacion por falta de pip.
- La disponibilidad de Impacket mejora cuando `python3-impacket` esta presente en repositorios apt.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.12.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/docs/INDEX.md)
