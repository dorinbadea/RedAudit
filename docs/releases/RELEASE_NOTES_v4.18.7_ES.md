# RedAudit v4.18.7 - Recuento correcto de PCAPs

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.7/docs/releases/RELEASE_NOTES_v4.18.7.md)

## Resumen

Este parche corrige el recuento inflado de PCAPs en el resumen final del CLI usando metadatos del run.

## Añadido

- Ninguno.

## Mejorado

- Ninguno.

## Corregido

- El resumen CLI ahora informa el recuento correcto de PCAPs del run actual, sin incluir capturas de otros directorios.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualización

Sin cambios incompatibles. Actualiza a v4.18.7 para obtener un recuento correcto en el resumen CLI.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.7/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.18.7/docs/INDEX.md)
