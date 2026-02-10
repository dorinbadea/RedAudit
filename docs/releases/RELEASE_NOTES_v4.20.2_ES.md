# RedAudit v4.20.2 - Pulido UX del wizard de Scope Expansion

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.2/docs/releases/RELEASE_NOTES_v4.20.2.md)

## Resumen

Este parche mejora la experiencia del wizard de Scope Expansion para operadores no expertos, manteniendo sin cambios la semántica de ejecución en runtime.

## Anadido

- No se introducen nuevos escáneres de runtime ni nuevos packs de protocolo en este parche.

## Mejorado

- La configuración avanzada de Scope Expansion pasa a ser guiada con opciones explícitas `Automático (Recomendado)` y `Manual`.
- Las etiquetas de packs de política de Leak Following ahora son más legibles (`Safe Default`, `Safe Strict`, `Safe Extended`) en prompts interactivos.
- Al elegir `No (por defecto)` en Scope Expansion avanzado, el wizard confirma explícitamente que se aplican defaults automáticos recomendados.
- Si se dejan vacíos campos CSV manuales en Scope Expansion avanzado, ahora se aplica fallback determinista a defaults automáticos seguros.

## Corregido

- Flujo ambiguo de prompts avanzados del wizard para controles de Scope Expansion.
- Incertidumbre operativa sobre qué ocurre cuando se dejan vacíos campos CSV avanzados.

## Pruebas

- Validación interna completada.

## Actualizacion

- No se requiere ninguna acción.
