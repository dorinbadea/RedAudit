# RedAudit v4.18.19 - Consistencia de UI y Snapshot de Configuracion

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.19/docs/releases/RELEASE_NOTES_v4.18.19.md)

## Summary

Esta version alinea el idioma de la UI, mejora el estilo de progreso y amplia los snapshots de configuracion para mayor trazabilidad.

## Added

- None.

## Improved

- La salida Rich aplica el color de estado a todas las lineas del mensaje para un contraste consistente.
- El snapshot de configuracion ahora incluye `deep_id_scan`, `trust_hyperscan` y `nuclei_timeout`.

## Fixed

- Los cambios de idioma actualizan el UI manager y evitan mezcla EN/ES.
- El filtrado WARN reconoce palabras clave en espanol durante el progreso.
- Dependencias, fallos de autenticacion y errores de escaneo usan cadenas localizadas.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v --cov=redaudit --cov-report=term-missing`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.19.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.19/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.19/docs/INDEX.md)
