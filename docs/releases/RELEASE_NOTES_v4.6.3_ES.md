# RedAudit v4.6.3 - Hotfix del Asistente

**Fecha:** 11-01-2026
**Tipo:** Hotfix Release

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.3/docs/releases/RELEASE_NOTES_v4.6.3.md)

Este hotfix soluciona un problema de UX donde la optimización "Trust HyperScan" estaba disponible vía CLI pero ausente en el Asistente Interactivo.

### 🐛 Correcciones y Mejoras UX

- **Asistente**: Añadido el prompt interactivo faltante para "Trust HyperScan" en el perfil **Custom** (Paso 2).
- **Valores por defecto**: `Trust HyperScan` activado por defecto en los perfiles **Express** y **Standard** para un rendimiento inmediato en redes silenciosas.
- **Modo Exhaustivo**: Desactiva explícitamente `Trust HyperScan` (se preserva el modo paranoico).

---
**Changelog Completo**: <https://github.com/dorinbadea/RedAudit/compare/v4.6.2...v4.6.3>
