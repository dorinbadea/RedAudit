# RedAudit v4.20.9 - Estabilizacion de Progreso Live Dual en Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.9/docs/releases/RELEASE_NOTES_v4.20.9.md)

## Resumen

Este parche refuerza la UX de progreso de Nuclei en ejecuciones largas al mantener una barra live dedicada y una linea live paralela de telemetria, reduciendo ruido en terminal sin cambiar la semantica de escaneo.

## Anadido

- No se anaden flags nuevos de runtime en este parche.

## Mejorado

- El progreso live de Nuclei mantiene ahora la barra principal y la telemetria en dos lineas sincronizadas.
- El contexto de profundidad de split, lotes activos y tiempos se actualiza in-place para mejorar legibilidad en ventanas largas de timeout/reintento.

## Corregido

- Se corrigen rafagas repetitivas de logs de telemetria Nuclei (`[nuclei] active batches ...`) que antes saturaban la salida de terminal en ejecuciones largas.

## Pruebas

Validacion interna completada.

## Actualizacion

No se requiere ninguna accion.
