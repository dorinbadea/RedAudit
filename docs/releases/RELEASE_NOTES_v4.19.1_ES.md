# RedAudit v4.19.1 - Presupuesto Nuclei con limite real

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/docs/releases/RELEASE_NOTES_v4.19.1.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/docs/releases/RELEASE_NOTES_v4.19.1_ES.md)

## Summary

Corrige el presupuesto de tiempo de Nuclei y aclara el progreso/informes cuando el presupuesto termina una ejecucion.

## Added

- Ninguno.

## Improved

- Los resumenes ahora incluyen `budget_exceeded` cuando el presupuesto termina la fase de Nuclei.
- Manual y uso aclaran el presupuesto total, los lotes secuenciales y los artefactos de reanudacion.

## Fixed

- Los lotes se limitan al tiempo restante y se guardan objetivos pendientes si se agota a mitad de lote.
- El detalle de progreso usa el color de estado y las paradas por presupuesto no muestran avisos de timeout.

## Testing

- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.1.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/docs/INDEX.md)
