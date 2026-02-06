# RedAudit v4.18.11 - Sync del updater y trazabilidad HTML

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.11/docs/releases/RELEASE_NOTES_v4.18.11.md)

## Summary

Esta versión mejora la experiencia de actualización, la transparencia del pipeline en HTML y la guía de mantenimiento del laboratorio.

## Added

- Ninguno.

## Improved

- El updater refresca tags y hace fast‑forward de `main` cuando el repo está limpio para evitar prompts desfasados.
- Los resúmenes del pipeline en HTML incluyen el resultado del escaneo autenticado cuando está disponible.
- El script del laboratorio aplica rotación de logs de Docker para evitar crecimiento excesivo.
- El contenedor SMB `.30` se recrea durante la instalación para evitar configuraciones obsoletas.
- La guía del laboratorio ahora incluye limpieza completa y flags de rotación para ejecuciones manuales.

## Fixed

- Las pistas de timeout DHCP ya no indican ausencia de IPv4 si no se pudo verificar la interfaz.
- Los informes HTML en español traducen los errores del pipeline (por ejemplo, timeouts DHCP).

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.11 para un updater más claro, mejor trazabilidad HTML y un lab más seguro.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.11/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.11/docs/INDEX.md)
