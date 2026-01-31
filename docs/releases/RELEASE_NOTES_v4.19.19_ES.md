# RedAudit v4.19.19 - Correcciones de renderizado del progreso Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/docs/releases/RELEASE_NOTES_v4.19.19.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/docs/releases/RELEASE_NOTES_v4.19.19_ES.md)

## Summary

Corrige el renderizado del progreso de Nuclei y guarda objetivos pendientes cuando los timeouts dejan la ejecucion como parcial.

## Added

- None.

## Improved

- None.

## Fixed

- Los mensajes de estado respetan los colores de warning/error durante el progreso Rich.
- El progreso de Nuclei ya no reporta 100% mientras los lotes siguen ejecutándose (detalle ES).
- Las ejecuciones parciales por timeout guardan objetivos pendientes para reanudar.

## Testing

- `pytest tests/cli/test_ui_manager.py tests/core/test_auditor_orchestrator.py -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.19.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/docs/INDEX.md)
