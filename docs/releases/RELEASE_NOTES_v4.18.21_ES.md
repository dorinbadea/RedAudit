# RedAudit v4.18.21 - Seguridad de refresco en home

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.21/docs/releases/RELEASE_NOTES_v4.18.21.md)

## Summary

Las actualizaciones del sistema ahora preservan cambios locales en `~/RedAudit` haciendo un backup y refrescando la copia en home para mantener la documentación al día.

## Added

- None.

## Improved

- Las actualizaciones del sistema hacen backup de `~/RedAudit` con cambios y refrescan la copia en home en lugar de omitirla.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v --cov=redaudit --cov-report=term-missing`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.21.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.21/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.21/docs/INDEX.md)
