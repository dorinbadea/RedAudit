# RedAudit v4.18.4 - Trazabilidad de informes y transparencia de discovery

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.4/docs/releases/RELEASE_NOTES_v4.18.4.md)

## Resumen

Esta versión mejora la trazabilidad en los informes y muestra errores de discovery para mayor transparencia.

## Añadido

- Ninguno.

## Mejorado

- Los sospechosos de Nuclei ahora se listan en HTML/TXT para revisión.

## Corregido

- Los errores de Net Discovery ahora aparecen en secciones HTML/TXT del pipeline.
- Los snapshots de configuración ahora guardan `nuclei_profile` y `nuclei_full_coverage` en el resumen.
- DHCP ahora usa la interfaz de la ruta por defecto, prueba todas las interfaces IPv4 en modo completo y reporta timeouts como sin respuesta.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualizar

- Sin pasos especiales. Actualiza y ejecuta como siempre.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.4/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.4/docs/INDEX.md)
