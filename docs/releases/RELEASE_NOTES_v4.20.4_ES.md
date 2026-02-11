# RedAudit v4.20.4 - Validación de Artefactos y Observabilidad de Reanudación Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.4/docs/releases/RELEASE_NOTES_v4.20.4.md)

## Resumen

Este parche mejora los controles de fiabilidad de salida y la observabilidad de reanudación de Nuclei, sin cambiar la semántica de targeting del escaneo.

## Añadido

- Se añade un gate reproducible para validar carpetas de escaneo completadas:
  - `scripts/check_scan_artifacts.py`
  - `redaudit/utils/scan_artifact_gate.py`
- El gate valida:
  - completitud/lectura de artefactos en `run_manifest.json`
  - integridad mínima de cabeceras PCAP
  - contrato JSON/JSONL en `summary.json`, `assets.jsonl` y `findings.jsonl`
- Se añade modo estricto para fallar de forma inmediata cuando faltan ficheros SIEM o campos obligatorios.

## Mejorado

- El detalle de progreso de Nuclei muestra de forma explícita el contexto de tiempo transcurrido por sub-lote y una semántica más clara de profundidad de split durante reintentos por timeout.
- El reporte HTML y el resumen de pipeline exponen ahora contexto de reanudación para ejecuciones parciales:
  - `resume_pending`
  - `resume_count`
  - `last_resume_at`
  - `resume_state_file`

## Corregido

- Se normaliza la serialización de metadatos de reanudación de Nuclei entre salidas para evitar campos ambiguos o ausentes en consumidores downstream.

## Pruebas

Validación interna completada.

## Actualización

No se requiere ninguna acción.
