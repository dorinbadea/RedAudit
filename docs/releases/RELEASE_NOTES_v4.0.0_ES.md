# Notas de Lanzamiento v4.0.0

[![EN](https://img.shields.io/badge/lang-EN-blue.svg)](RELEASE_NOTES_v4.0.0.md)

**Fecha de Lanzamiento:** 2026-01-04
**Nombre en Clave:** Reestructuración de Arquitectura y Seguridad de Tipos

## Resumen

RedAudit v4.0.0 marca la evolución arquitectónica más significativa en la historia del proyecto. Esta versión completa la transición de un monolito basado en herencia a una arquitectura moderna basada en composición y potenciada por modelos de datos robustos. Este cambio garantiza la seguridad de tipos, elimina clases enteras de errores por claves de diccionario y proporciona una base sólida para la extensibilidad futura sin cambios rupturistas.

## Nuevas Características

### Modelos de Datos Robustos

- **Dataclass Host**: Se han reemplazado los diccionarios ad-hoc por un objeto formal `Host`. Esta única fuente de verdad gobierna ahora IP, MAC, Proveedor, SO, Puertos y Vulnerabilidades a lo largo de todo el pipeline.
- **Seguridad de Tipos**: Las nuevas dataclasses `Service` y `Vulnerability` aseguran un manejo de datos consistente desde el escaneo hasta el informe.

### Composición Arquitectónica

- **Refactor Heredado**: El antiguo `AuditorScan` y otras rutas heredadas han sido refactorizadas en un `NetworkScanner` compuesto y componentes modulares.
- **Núcleo Más Limpio**: El bucle principal en `auditor.py` es ahora un orquestador limpio que pasa objetos `Host` entre componentes especializados.

## Correcciones

### Estabilidad de Smart Scan y Asistente

- **Metadatos Smart Scan**: Se corrigió un problema donde los datos de decisión de `smart_scan` (puntuaciones, razones de escalada) no persistían correctamente en el objeto `Host` en la nueva arquitectura.
- **UI del Asistente**: Se resolvieron problemas de `AttributeError` y `TypeError` en el manejo de colores de la UI del Asistente, asegurando que los mocks de `UIManager` estén correctamente tipados en las pruebas.
- **Suite de Pruebas**: Remediación integral de la suite de pruebas para alinearse con la nueva arquitectura orientada a objetos.

## Pruebas

- 1264+ pruebas pasando
- Cobertura completa de los nuevos modelos `Host` y `NetworkScanner`
- Cobertura: ~84%

## Notas de Actualización

Esta es una versión mayor con cambios arquitectónicos internos.

- **Configuración**: El archivo `config.json` existente es compatible.
- **Informes**: El esquema de informe JSON permanece compatible hacia atrás, aunque la representación interna es mucho más estricta.

---

[Historial de Cambios Completo](../../CHANGELOG_ES.md) | [Índice de Documentación](../INDEX_ES.md)
