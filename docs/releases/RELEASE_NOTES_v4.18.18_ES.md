# RedAudit v4.18.18 - Contraste del Wizard y Enriquecimiento de Bajo Impacto

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.18/docs/releases/RELEASE_NOTES_v4.18.18.md)

## Summary

Esta version anade una sonda HTTP/HTTPS opcional para hosts con solo vendor y cero puertos abiertos, mejora el contraste del wizard y limita los timeouts tras split de Nuclei para evitar esperas largas.

## Added

- El enriquecimiento Phase 0 permite una sonda HTTP/HTTPS corta para hosts con solo vendor y cero puertos abiertos.

## Improved

- Los menus del wizard muestran las opciones no seleccionadas en azul y resaltan los valores por defecto en los prompts.
- Los reintentos tras dividir lotes de Nuclei limitan el timeout para reducir esperas en objetivos lentos.

## Fixed

- Los resumenes smart scan ahora respetan `low_impact_enrichment` cuando la configuracion es un `ConfigurationContext`.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.18 para prompts mas claros y reintentos de Nuclei mas seguros.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.18/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.18/docs/INDEX.md)
