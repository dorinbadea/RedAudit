# RedAudit v4.20.7 - Claridad de Progreso y Duracion en Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.7/docs/releases/RELEASE_NOTES_v4.20.7.md)

## Resumen

Este parche mejora la visibilidad operativa de Nuclei sin cambiar la semantica de escaneo. La salida de progreso es mas legible en terminal y la duracion reportada pasa a medirse de forma explicita con tiempo wall-clock tanto en ejecucion inicial como en reanudacion.

## Anadido

- Nuevos campos de tiempo de Nuclei en pipeline/report:
  - `last_run_elapsed_s`
  - `last_resume_elapsed_s`
  - `nuclei_total_elapsed_s`

## Mejorado

- El progreso de Nuclei usa ahora un formato compacto en dos lineas:
  - Linea de barra de progreso
  - Linea de telemetria (`lote`, `profundidad de division`, `tiempo de sub-lote`, `tiempo total`)
- El resumen HTML de Nuclei muestra ahora:
  - Duracion de la ultima ejecucion
  - Duracion de la ultima reanudacion
  - Duracion total acumulada de Nuclei
- Los mensajes de cierre imprimen duracion explicita:
  - `Nuclei completado en ...`
  - `Reanudacion de Nuclei completada en ...`

## Corregido

- Se corrige la contabilidad de duracion para usar tiempo wall-clock real alrededor de run/reanudar.
- Se corrige la salida del prompt con timeout para que el auto-continue no colisione con el siguiente log.

## Pruebas

Validacion interna completada.

## Actualizacion

No se requiere ninguna accion.
