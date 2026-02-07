# RedAudit v4.19.47 - Robustez en Updater y HyperScan

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.47/docs/releases/RELEASE_NOTES_v4.19.47.md)

## Resumen

Este parche mejora la fiabilidad en ejecucion y la resiliencia del flujo de actualizacion sin cambiar el uso normal para el usuario.

## Anadido

- No hay funciones nuevas orientadas al usuario.

## Mejorado

- El clonado de actualizaciones ahora usa lectura de salida no bloqueante, manteniendo fiable el timeout cuando el comando deja de emitir salida.

## Corregido

- El fallback de escaneo completo en HyperScan ahora cierra corrutinas pendientes de forma segura cuando falla la ejecucion del event loop.
- El diagnostico del updater ahora diferencia entre ausencia de `git` y otros fallos por ficheros faltantes.

## Pruebas

- Validacion interna completada.

## Actualizacion

- No se requiere ninguna accion.
