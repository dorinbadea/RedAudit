# Notas de Lanzamiento v4.0.2

[![EN](https://img.shields.io/badge/lang-EN-blue.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.0.2/docs/releases/RELEASE_NOTES_v4.0.2.md)

**Fecha de lanzamiento:** 2026-01-05
**Nombre en clave:** Consolidación de Pruebas

## Resumen

RedAudit v4.0.2 es una versión de mantenimiento centrada en la estructura de la suite
de pruebas, mejoras de cobertura significativas y estabilidad de CI.

## Destacados

- **Estructura de Pruebas**: Reorganización de los tests en `tests/core`, `tests/cli`,
  `tests/utils` y `tests/integration` para una responsabilidad más clara.
- **Mejoras de Cobertura**: Añadida cobertura significativa en componentes del auditor,
  gestión de vulnerabilidades, flujos del asistente y HyperScan.
- **Documentación**: Actualización de las directrices de merge y CI en `AGENTS.md`.

## Correcciones

- **Parcheo de Tamaño de Terminal**: Evitado el parcheo global de
  `shutil.get_terminal_size` que podía romper `pytest` en CI.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Notas de Actualización

No se requieren cambios de configuración. Los informes existentes siguen siendo
compatibles.

---

[Historial de Cambios Completo](../../CHANGELOG_ES.md) | [Índice de Documentación](../INDEX_ES.md)
