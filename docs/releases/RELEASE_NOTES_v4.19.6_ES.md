# RedAudit v4.19.6 - Progreso de Nuclei y contraste INFO

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/docs/releases/RELEASE_NOTES_v4.19.6.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/docs/releases/RELEASE_NOTES_v4.19.6_ES.md)

## Summary

El progreso de reanudacion de Nuclei informa correctamente los lotes completados en paralelo y la salida INFO usa el azul estandar para mejor legibilidad.

## Added

- None.

## Improved

- El detalle de progreso refleja el recuento de lotes completados en paralelo.

## Fixed

- Las lineas INFO ya no aparecen en blanco en terminales que muestran el cian como blanco.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.6.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/docs/INDEX.md)
