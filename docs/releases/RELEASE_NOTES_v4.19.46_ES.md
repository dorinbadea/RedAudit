# RedAudit v4.19.46 - Cobertura Estratégica y Resiliencia

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.46/docs/releases/RELEASE_NOTES_v4.19.46.md)

## Resumen

Esta versión se centra en la fiabilidad de grado industrial con una cobertura de pruebas exhaustiva y un análisis de entrada resiliente en los módulos principales.

## Mejorado

- **Cobertura Estratégica**: Incremento de la cobertura de tests en `updater.py` (99.67%), `jsonl_exporter.py` (100%), `config.py` (99.48%), `auditor_scan.py` (96.30%) y `auditor_vuln.py` (97.48%) cubriendo casos borde y rutas de excepción.

## Corregido

- **Resiliencia en expansión de alcance**: Corregido un fallo potencial en `build_leak_follow_targets` al procesar datos de puerto malformados o no numéricos procedentes de candidatos.

## Pruebas

- Alcanzada cobertura >99% en los módulos principales modificados.
- Superados los controles de calidad de pre-commit.

## Actualización

- No se requiere ninguna acción.
