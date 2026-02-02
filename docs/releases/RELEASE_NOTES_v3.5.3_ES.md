# RedAudit v3.5.3

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.5.3.md)

**Fecha**: 2025-12-18
**Tipo**: Patch Release (Documentación y Calidad de Código)

##  Novedades

### Integridad Documental y Normalización

Esta versión se centra en asegurar que la documentación refleje con precisión el código base ("sin humo"), reparar enlaces rotos y optimizar la estructura del proyecto.

- **Normalización de Docs**: Consolida la documentación en la carpeta raíz `docs/` (eliminando `docs/en/` y `docs/es/`) usando sufijos `.en.md` y `.es.md`.
- **Verificación de Roadmap**: Auditoría estricta del roadmap para separar funcionalidades *Planeadas* de las *Implementadas*, asegurando honestidad técnica.
- **Reescritura de Guía Didáctica**: Reestructuración completa de `DIDACTIC_GUIDE` (EN/ES) como recurso pedagógico real para instructores, eliminando duplicidad con el manual.
- **Reparación de Enlaces**: Corrección de links internos rotos en `pyproject.toml`, `README` y templates.

##  Correcciones

- **Docs**: Corregido `pyproject.toml` que apuntaba a rutas inexistentes.
- **Docs**: Corregidos encabezados redundantes y falta de especificadores de lenguaje en Markdown (Linting compliance).
- **Estructura**: Formalizado el uso de `docs/INDEX.md` como punto de entrada.

## Cambios

| Componente | Cambio |
| :--- | :--- |
| **Docs** | Estructura aplanada (`docs/MANUAL.en.md`, etc.) |
| **Roadmap** | Estado de implementación verificado para features Red Team |
| **Didáctico** | Nuevo formato enfocado a instructores con planes de sesión |

## Enlaces Rápidos

- [Manual (ES)](../../MANUAL.es.md)
- [Guía de Uso (ES)](../../USAGE.es.md)
- [Historial de Cambios](../../ES/CHANGELOG_ES.md)
