# RedAudit v4.18.16 - Regla de cobertura y expansion de tests

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.16/docs/releases/RELEASE_NOTES_v4.18.16.md)

## Summary

Esta version incorpora una regla de cobertura en el workflow y amplia los tests automatizados para llegar al 98%.

## Added

- El workflow exige cobertura del 100% para el codigo modificado y rutas nuevas.

## Improved

- Se amplio la cobertura de tests del updater para alcanzar 98% global.

## Fixed

- Ninguno.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -q --cov=redaudit --cov-report=term-missing`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.16 para la regla de cobertura y la ampliacion de tests.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.16/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.16/docs/INDEX.md)
