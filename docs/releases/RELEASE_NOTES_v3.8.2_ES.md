# Notas de Versión RedAudit v3.8.2

**Fecha de lanzamiento:** 2025-12-20

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.2.md)

## Resumen

RedAudit v3.8.2 es un release de pulido UX enfocado en **navegación del wizard** y **mejoras de feedback visual**.

## Añadido

### Navegación del Wizard (v3.8.1)

- Navegación paso a paso con opción "< Volver" en todos los menús del wizard
- Permite revisar y modificar elecciones previas sin reiniciar

### Marca de Agua en Informes HTML

- Footer profesional con licencia GPLv3, crédito del autor (Dorin Badea) y enlace al repositorio GitHub

## Corregido

### Display de Barras de Progreso

- Eliminado `SpinnerColumn` que causaba congelaciones durante fases largas de Net Discovery y Deep Scan
- El progreso ahora muestra: `descripción + barra + porcentaje + tiempo transcurrido`

## Documentación

- [Registro de cambios completo](../../ES/CHANGELOG_ES.md)
- [Roadmap](../ROADMAP.es.md)
