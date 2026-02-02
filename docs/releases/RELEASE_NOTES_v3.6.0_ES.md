# RedAudit v3.6.0

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.6.0.md)

**Fecha**: 2025-12-18
**Tipo**: Minor Release

##  Novedades

### Nuclei ahora es accesible de forma correcta (opt-in)

El soporte de Nuclei ahora es coherente con el UX y la documentación:

- Se habilita desde el wizard (modo completo) o por flags de CLI: `--nuclei` / `--no-nuclei`
- Se puede guardar como default persistente (`~/.redaudit/config.json`)
- El instalador incluye `nuclei` en la lista de dependencias recomendadas (apt)

### Salida más limpia sin perder contexto

- Las fases de hosts y vulnerabilidades reducen líneas ruidosas mientras hay barras de progreso activas.
- La propia línea de progreso muestra “qué está haciendo” (herramienta/técnica) usando el detalle suprimido.
