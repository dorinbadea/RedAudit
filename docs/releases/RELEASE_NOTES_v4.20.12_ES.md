# RedAudit v4.20.12 - Progreso Compacto de Nuclei y Agregacion de Timeouts

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.12/docs/releases/RELEASE_NOTES_v4.20.12.md)

## Resumen

Esta version patch mejora la usabilidad de Nuclei en terminal durante ciclos largos de timeout/reintento, compactando ruido live y conservando detalle en un unico bloque final agrupado.

## Anadido

- Se agregan campos de agregacion de timeout de Nuclei en salidas pipeline/report: `timeout_batches_count`, `timeout_events_count` y `timeout_summary_compact`.

## Mejorado

- El progreso live de Nuclei suprime detalle repetitivo por timeout mientras la barra activa esta en pantalla.
- El reporte de timeout al final de fase imprime un unico bloque resumido con contexto por lote.
- `run_manifest.json` refleja secciones adicionales del pipeline (`topology`, `agentless_verify`, `scope_expansion`) para mayor paridad de salida.

## Corregido

- Se reduce el riesgo de corrupcion visual de lineas en terminal por colision entre warnings/logs y render live del progreso.

## Testing

Validacion interna completada.

## Upgrade

No se requiere accion.
