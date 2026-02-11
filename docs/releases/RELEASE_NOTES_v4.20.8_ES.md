# RedAudit v4.20.8 - Reduccion de Ruido en Progreso de Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.8/docs/releases/RELEASE_NOTES_v4.20.8.md)

## Resumen

Este parche mejora la usabilidad en terminal durante ejecuciones largas de Nuclei reduciendo el ruido de lineas de progreso. La logica de escaneo y la semantica de targeting no cambian.

## Anadido

- No se anaden funciones nuevas de runtime en este parche.

## Mejorado

- La telemetria de Nuclei reporta cambios de estado compactos en lugar de cambios por segundo del contador de tiempo.
- La salida de progreso se mantiene legible en ciclos largos de timeout/reintento.
- Se acorta la redaccion de telemetria para reducir saltos de linea en terminales estrechos.

## Corregido

- El seguimiento de estado de progreso ahora normaliza claves de telemetria (`lotes activos`, `profundidad de division`, reintentos) e ignora valores volatiles de `tiempo de sub-lote` que antes provocaban tormentas de logs.

## Pruebas

Validacion interna completada.

## Actualizacion

No se requiere ninguna accion.
