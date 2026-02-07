# RedAudit v4.19.52 - Consistencia de idioma en informe HTML

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.52/docs/releases/RELEASE_NOTES_v4.19.52.md)

## Resumen

Este parche alinea el informe HTML con el idioma seleccionado en la ejecucion y mejora la claridad del dashboard cuando no hay datos para las graficas.

## Anadido

- No hay nuevas funcionalidades de usuario final en esta version.

## Mejorado

- `report.html` ahora respeta el idioma activo de ejecucion (`en` o `es`).
- Las graficas del dashboard ahora muestran estados explicitos sin datos en lugar de parecer rotas.

## Corregido

- Las ejecuciones en espanol ya no generan un `report_es.html` adicional; ahora la salida es un unico `report.html` en el idioma elegido.
- Los perfiles sin hallazgos o sin distribucion de puertos ahora muestran un mensaje claro de falta de datos.

## Pruebas

- Validacion interna completada.

## Actualizacion

- No se requiere ninguna accion.
