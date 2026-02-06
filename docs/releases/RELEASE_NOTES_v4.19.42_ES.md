[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.42/docs/releases/RELEASE_NOTES_v4.19.42.md)

# RedAudit v4.19.42 - Endurecimiento de consistencia en reanudacion e informes

## Summary

Este parche mejora la coherencia de informes en ejecuciones interrumpidas y reanudadas, alineando contadores de Nuclei, indexacion de artefactos de resume, totales de evidencia de riesgo por host y fallback de hostname en salidas JSONL.

## Added

- `run_manifest.json` incluye ahora un objeto `nuclei_resume` (cuando exista) con:
  - conteo de objetivos pendientes
  - numero de reanudaciones
  - marcas de tiempo de ultima/ultima actualizacion
  - metadatos de perfil/salida
- Se añade `counts.nuclei_pending_targets` al bloque de conteos del manifiesto.

## Improved

- El resumen de Nuclei diferencia ahora:
  - `targets_total` (objetivos efectivos ejecutados tras optimizacion)
  - `targets_pre_optimization` (total descubierto antes de optimizar)
- Mejorada la consistencia de hostname en JSONL usando fallback de DNS inverso cuando `hostname` esta vacio.

## Fixed

- El orden de cierre de session logs garantiza que `run_manifest.json` incluya los artefactos `session_resume_*` mas recientes.
- El desglose de riesgo ahora contabiliza correctamente `finding_total` y evita mostrar `risk findings 1/0` en TXT/HTML.
- Corregida la deriva de hostname entre TXT/HTML y JSONL en activos resueltos solo por DNS inverso.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Actualiza a `v4.19.42` desde el repositorio oficial.
2. Ejecuta un escaneo con una o mas reanudaciones de Nuclei y verifica que `run_manifest.json` incluya `nuclei_resume`.
3. Confirma que los hostnames de JSONL coinciden con el fallback mostrado en TXT/HTML para activos solo con DNS inverso.
