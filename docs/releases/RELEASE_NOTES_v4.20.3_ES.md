# RedAudit v4.20.3 - Guardarraíles de Cobertura y Estabilización de Tests

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.3/docs/releases/RELEASE_NOTES_v4.20.3.md)

## Resumen

Este parche cierra el trabajo local de recuperación, refuerza los gates de calidad de cobertura y estabiliza los tests de autenticación en ejecuciones completas de gran tamaño.

## Añadido

- Se añaden utilidades de cobertura por archivo cambiado:
  - `scripts/check_changed_coverage.py`
  - `redaudit/utils/coverage_gate.py`
- Se integra en CI/local la validación `>=98%` de cobertura para archivos cambiados `redaudit/*.py`.

## Mejorado

- Se mejora el flujo de paridad local en `scripts/ci_local.sh` para generar `coverage.json` y ejecutar validación de cobertura por archivo cambiado.
- Se endurece el determinismo de tests SMB/SNMP recargando módulos mockeados explícitamente y evitando efectos por orden de importación.

## Corregido

- Se mantiene y valida `tests/core/test_auditor_run_complete_scan.py` en la rama activa.
- Se preserva compatibilidad en `auditor_scan` para contenedores mixtos de tags y formatos mDNS legacy en fixtures.

## Pruebas

Validación interna completada.

## Actualización

No se requiere ninguna acción.
