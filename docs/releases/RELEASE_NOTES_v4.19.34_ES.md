# RedAudit v4.19.34 - Trazabilidad del desglose de riesgo

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.34/docs/releases/RELEASE_NOTES_v4.19.34.md)

## Summary

El desglose de riesgo separa ahora evidencia y heurística, los fallos del escaneo autenticado se muestran en los informes, y las exportaciones de activos incluyen puertos abiertos para inventario.

## Added

- None.

## Improved

- Los tooltips del desglose de riesgo muestran señales con evidencia y heurística, junto con el origen del CVSS máximo.
- Los fallos del escaneo autenticado aparecen en HTML y en los resúmenes.

## Fixed

- `assets.jsonl` ahora incluye puertos abiertos para inventario posterior.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No hay cambios incompatibles. Actualiza a v4.19.34.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.34/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.34/docs/INDEX.md)
