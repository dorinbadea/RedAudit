# RedAudit v4.18.2 - Colores UI y Consistencia de Informes

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.2/docs/releases/RELEASE_NOTES_v4.18.2.md)

## Resumen

Esta version corrige la consistencia de colores durante el progreso y alinea los conteos de informes y manifiestos con los artefactos generados.

## Anadido

- Ninguno.

## Mejorado

- La cobertura completa de Nuclei ahora sigue el perfil seleccionado (Full => Si, Balanced/Fast => No).

## Corregido

- Los colores de estado ahora se muestran correctamente durante el progreso de HyperScan.
- Las fuentes de vulnerabilidades en el resumen ahora coinciden con los hallazgos consolidados.
- El conteo de PCAP en el manifiesto ahora refleja todos los artefactos listados.
- Texto del prompt de cobertura completa de Nuclei en espanol ajustado para claridad.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualizar

- Sin pasos especiales. Actualiza y ejecuta como siempre.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.2/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.2/docs/INDEX.md)
