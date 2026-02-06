# RedAudit v4.18.3 - Progreso HyperScan y Claridad del Asistente Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.3/docs/releases/RELEASE_NOTES_v4.18.3.md)

## Resumen

Esta version mejora el progreso de HyperScan y aclara las opciones del asistente de Nuclei.

## Anadido

- Ninguno.

## Mejorado

- Las etiquetas de perfil de Nuclei ahora describen el alcance de las plantillas, no los puertos.
- La pregunta de cobertura completa ahora aclara que escanea todos los puertos HTTP detectados, mas alla de 80/443.

## Corregido

- El progreso de HyperScan ya no intercala lineas por host encima de la barra de progreso.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualizar

- Sin pasos especiales. Actualiza y ejecuta como siempre.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.3/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.3/docs/INDEX.md)
