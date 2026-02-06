# RedAudit v4.18.1 - Consistencia de Informes y Politica de Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.1/docs/releases/RELEASE_NOTES_v4.18.1.md)

## Resumen

Esta version alinea el reporte de Nuclei con el estado real de ejecucion y mantiene la intencion de auditoria cuando la cobertura completa esta activada.

## Anadido

- Ninguno.

## Mejorado

- El resumen de Nuclei en HTML y TXT ahora muestra resultados parciales y solo sospechosos.

## Corregido

- El estado parcial de Nuclei, lotes con timeout y lotes fallidos ahora se muestran en los informes.
- Los conteos de fuentes de vulnerabilidades reflejan hallazgos enriquecidos en lugar de `unknown`.
- El cambio automatico a auto-fast se omite cuando la cobertura completa esta activada para respetar el perfil seleccionado.

## Testing

- `pytest tests/ -v`

## Actualizar

- Sin pasos especiales. Actualiza y ejecuta como siempre.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.1/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.1/docs/INDEX.md)
