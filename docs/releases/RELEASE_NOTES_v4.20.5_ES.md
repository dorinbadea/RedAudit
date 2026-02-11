# RedAudit v4.20.5 - Estabilidad de Reanudación Nuclei y Endurecimiento del Contrato NDJSON

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.5/docs/releases/RELEASE_NOTES_v4.20.5.md)

## Resumen

Este parche corrige un error real de ejecución en la reanudación de Nuclei, mejora la claridad operativa en progreso/reportes y endurece la validación contractual de artefactos NDJSON.

## Añadido

- Se amplía la validación de artefactos para comprobar los flujos brutos NDJSON de Nuclei:
  - `nuclei_output.json`
  - `nuclei_output_resume.json`
- Se añaden líneas de estado explícitas para el operador en runtime de scope expansion:
  - contadores runtime de sondas IoT
  - número de objetivos añadidos por leak-follow antes de Nuclei

## Mejorado

- El detalle de progreso de Nuclei separa ahora de forma clara:
  - contexto de tiempo transcurrido del sub-lote
  - temporizador total transcurrido de Nuclei
  - semántica de profundidad de split (`actual/maximo`)
- La visualización del modo en HTML ahora es consistente por idioma:
  - en UI inglesa muestra `fast/normal/full`
  - en UI española muestra `rapido/normal/completo`
  - los valores internos del contrato JSON no cambian por compatibilidad.
- La documentación EN/ES describe ahora explícitamente:
  - contrato NDJSON de los ficheros brutos de Nuclei
  - interpretación de `partial + resume_pending`
  - comportamiento esperado cuando `nuclei_output_resume.json` está vacío.

## Corregido

- Corregida la compatibilidad del prompt de reanudación de Nuclei: `ask_yes_no_with_timeout` acepta `timeout` y `timeout_s`, evitando el `TypeError` en flujos de reanudación.

## Pruebas

Validación interna completada.

## Actualización

No se requiere ninguna acción.
