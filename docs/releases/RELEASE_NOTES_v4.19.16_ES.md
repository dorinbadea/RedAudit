# RedAudit v4.19.16 - Coherencia de salida Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/docs/releases/RELEASE_NOTES_v4.19.16.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/docs/releases/RELEASE_NOTES_v4.19.16_ES.md)

## Summary

Aclara el reporte de Nuclei y el estado de reanudación para que los parciales y los hallazgos solo sospechosos queden reflejados de forma consistente.

## Added

- Ninguno.

## Improved

- El detalle de progreso de Nuclei ahora refleja lotes activos para reducir la confusión sobre el paralelismo.

## Fixed

- Los resúmenes de Nuclei ahora desactivan el éxito en parciales/timeouts y evitan el mensaje "completado (sin hallazgos)" cuando el resultado es incompleto.
- Los resúmenes de reanudación ahora conservan lotes con timeout/fallidos y recomputan el estado de éxito de forma consistente.
- La detección de etiquetas Sí/No ya no colorea "Normal" como "No".

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.16.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/docs/INDEX.md)
