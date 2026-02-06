# RedAudit v4.18.22 - Suelo de timeout en Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.22/docs/releases/RELEASE_NOTES_v4.18.22.md)

## Summary

RedAudit mantiene el timeout configurado por lote en Nuclei como suelo durante los reintentos tras split, para conservar cobertura en objetivos HTTP lentos.

## Added

- Ninguno.

## Improved

- Los reintentos tras split de Nuclei mantienen el suelo de timeout configurado para evitar perdida de cobertura en escaneos exhaustivos.

## Fixed

- Los reintentos tras split de Nuclei ya no reducen el timeout por debajo del configurado, reduciendo ejecuciones parciales en objetivos lentos.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.22.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.22/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.22/docs/INDEX.md)
