# RedAudit v4.18.9 - Correcciones de trazabilidad del informe

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.9/docs/releases/RELEASE_NOTES_v4.18.9.md)

## Summary

Esta version mejora la trazabilidad de los informes, reduce el ruido en topologia y corrige falsas fugas de red.

## Added

- Ninguno.

## Improved

- Los informes HTML muestran el perfil de Nuclei y la cobertura completa en el resumen.
- El descubrimiento ARP deduplica entradas IP/MAC identicas para reducir el ruido.

## Fixed

- Los objetivos en alcance se filtran de forma consistente en la deteccion de fugas de red.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.9 para informes mas limpios y fugas corregidas.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.9/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.9/docs/INDEX.md)
