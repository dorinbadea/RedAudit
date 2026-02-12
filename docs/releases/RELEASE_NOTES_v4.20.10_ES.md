# RedAudit v4.20.10 - Hardening de UX de Progreso Nuclei y Paridad de Artefactos

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.10/docs/releases/RELEASE_NOTES_v4.20.10.md)

## Resumen

Este parche mejora la experiencia operativa de Nuclei en ejecuciones largas al separar el render de la barra principal y la telemetria, reduciendo compresion visual y ruido en terminal. Tambien endurece la validacion de artefactos con checks estrictos de paridad para campos de reanudacion/tiempo de Nuclei entre resumen y manifiesto.

## Anadido

- Nuevo campo de reporte Nuclei: `targets_selected_after_optimization` para separar el total de objetivos seleccionados de los contadores solo de hosts optimizados.
- Checks de paridad estrictos en el gate de artefactos para metadatos de tiempo/reanudacion de Nuclei entre `summary.json` y `run_manifest.json`.

## Mejorado

- El progreso live de Nuclei usa ahora una sola linea de barra real y una linea separada solo de telemetria.
- La telemetria usa tokens compactos (`AB`/`B`, `SB`, `SD`) para mayor legibilidad en escaneos largos.
- El tiempo total transcurrido se muestra una sola vez en la barra principal, sin duplicados.
- El contexto HTML/TXT muestra de forma mas clara la metrica de objetivos seleccionados tras optimizacion.

## Corregido

- Menor ruido de terminal en ciclos largos de timeout/reintento de Nuclei mediante throttle y deduplicacion de telemetria.
- El fallback de logs de progreso evita spam por cambios de sub-lote, manteniendo transiciones de estado relevantes.

## Pruebas

Validacion interna completada.

## Actualizacion

No se requiere ninguna accion.
