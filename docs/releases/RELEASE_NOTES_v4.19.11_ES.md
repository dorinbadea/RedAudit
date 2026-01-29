# RedAudit v4.19.11 - Robustez del instalador

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/docs/releases/RELEASE_NOTES_v4.19.11.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/docs/releases/RELEASE_NOTES_v4.19.11_ES.md)

## Summary

El instalador ahora cubre huecos de paquetes en Ubuntu habilitando Universe/Multiverse y usando instalacion desde GitHub cuando apt no los ofrece.

## Added

- Sin cambios.

## Improved

- El flujo de instalacion continua cuando faltan paquetes individuales y aplica fallbacks especificos.

## Fixed

- La instalacion en Ubuntu ya no falla cuando faltan `exploitdb`, `enum4linux` o `nuclei` en apt.
- Nuclei, exploitdb/searchsploit y enum4linux se instalan desde GitHub cuando es necesario.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.11.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/docs/INDEX.md)
