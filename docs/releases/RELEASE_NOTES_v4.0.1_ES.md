# Notas de Lanzamiento v4.0.1

[![EN](https://img.shields.io/badge/lang-EN-blue.svg)](RELEASE_NOTES_v4.0.1.md)

**Fecha de Lanzamiento:** 2026-01-04
**Nombre en Clave:** Mantenimiento de Composición

## Resumen

RedAudit v4.0.1 es una versión de mantenimiento que estabiliza el flujo basado en
composición, refuerza la batería de pruebas y alinea la documentación con la arquitectura v4.

## Destacados

- **Adaptador de Composición**: El auditor principal delega el comportamiento de componentes
  vía `auditor_runtime.py`, manteniendo la orquestación por composición.
- **Higiene de Pruebas**: Eliminación de pruebas de relleno, cambio de nombre de las pruebas
  de componentes y endurecimiento del manejo de importación de OUI para evitar solicitudes
  externas.
- **Documentación**: Actualización de la hoja de ruta y de las notas de versión para reflejar
  la arquitectura.

## Correcciones

- **Ruido asíncrono**: Resueltas advertencias de corutinas en pruebas de HyperScan.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Notas de Actualizacion

No hay cambios de configuración. Los informes existentes siguen siendo compatibles.

---

[Historial de Cambios Completo](../../CHANGELOG_ES.md) | [Índice de Documentación](../INDEX_ES.md)
