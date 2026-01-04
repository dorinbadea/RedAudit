# Notas de la Versión v3.10.2

[![EN](https://img.shields.io/badge/lang-EN-blue.svg)](RELEASE_NOTES_v3.10.2.md)

**Fecha de Publicación:** 2026-01-04
**Nombre clave:** Nodo Auditor y Corrección de MAC

## Resumen

Esta versión corrige un error crítico donde las direcciones MAC no se mostraban en los informes HTML, e introduce la funcionalidad "Nodo Auditor" que identifica claramente la máquina del escáner en los informes de auditoría.

## Nuevas Funcionalidades

### Detección de Nodo Auditor

Las interfaces de red propias del escáner ahora se detectan automáticamente y se marcan en los informes HTML:

- Muestra `(Nodo Auditor)` en lugar de `-` en la columna MAC
- Funciona para todas las interfaces (Ethernet, Wi-Fi, etc.)
- Mejora el contexto profesional de las auditorías

### Fundamentos de Arquitectura (Interno)

Trabajo preparatorio para la arquitectura modular v4.0:

- Clase `UIManager` independiente para operaciones de UI
- `ConfigurationContext` envoltorio tipado para configuración
- `NetworkScanner` con utilidades de puntuación de identidad
- Propiedades adaptador para compatibilidad hacia atrás

## Correcciones

### Visualización de MAC en Informes HTML

Se corrigió un error donde las direcciones MAC no aparecían en los informes HTML a pesar de capturarse correctamente:

- **Causa raíz:** Discrepancia de clave (`host.get("mac")` vs `host.get("mac_address")`)
- **Corrección:** Ahora verifica ambas claves `mac_address` (canónica) y `mac` (legada)
- **Alcance:** Afectaba a todos los hosts sin escaneo profundo completo

## Pruebas

- Más de 1264 tests pasando
- 82 nuevos tests para componentes de arquitectura
- Cobertura: 84,72%

## Notas de Actualización

Esta es una versión de parche compatible hacia atrás. No requiere cambios de configuración.

---

[Registro de Cambios Completo](../../ES/CHANGELOG_ES.md) | [Índice de Documentación](../INDEX.md)
