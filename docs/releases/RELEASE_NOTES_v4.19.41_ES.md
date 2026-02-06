[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.41/docs/releases/RELEASE_NOTES_v4.19.41.md)

# RedAudit v4.19.41 - Alineacion de vendor canonico y transparencia de riesgo

## Summary

Este parche alinea la identidad de vendor y la evidencia de riesgo por host entre el enriquecimiento SIEM y las salidas para usuario, reduciendo ambiguedad y manteniendo el pipeline optimizado por defecto.

## Added

- Metadatos de vendor canonico en los registros SIEM por host:
  - `vendor_source`
  - `vendor_confidence`
- Contadores explicitos de evidencia de riesgo por host para CVEs de servicio (separando critical/high), exploits, firmas de backdoor y totales de hallazgos.

## Improved

- Las salidas HTML, TXT y JSONL usan ahora la misma fuente canonica de vendor para evitar deriva entre formatos.
- Los tooltips de riesgo en HTML y las secciones por host en TXT muestran de forma mas explicita los componentes de evidencia.

## Fixed

- Se reducen falsos positivos de vendor evitando que etiquetas genericas `*.fritz.box` fuercen inferencia AVM.
- Se mejora la clasificacion de inventario NAS mapeando por defecto a `server` las pistas Synology/QNAP/Asustor/TerraMaster.
- El vendor en ECS ahora sigue la resolucion canonica antes del fallback por deep-scan.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Actualiza a `v4.19.41` desde el repositorio oficial.
2. Ejecuta una auditoria y verifica que HTML/TXT/JSONL muestran el mismo vendor para el mismo host.
3. Confirma que el detalle de riesgo por host incluye contadores explicitos de evidencia (CVEs/exploits/backdoor/hallazgos).
