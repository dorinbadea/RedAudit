# Notas de Lanzamiento RedAudit v4.6.24

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.24/docs/releases/RELEASE_NOTES_v4.6.24.md)

## Resumen

**RedAudit v4.6.24** entrega una mejora critica de rendimiento para la integracion del escaner de vulnerabilidades Nuclei. Esta version aborda cuellos de botella significativos en escaneos de redes grandes introduciendo ejecucion paralela por lotes y corrigiendo un bug de logica de reintento que causaba bucles infinitos en timeouts.

## Mejorado

- **Lotes Nuclei Paralelos**: Los escaneos Nuclei ahora ejecutan hasta **4 lotes simultaneamente** (usando pool de hilos). Esto reduce dramaticamente el tiempo total de escaneo para redes grandes.
- **Lotes por Defecto mas Pequeños**: Reducido el tamaño de lote por defecto de 25 a **10** hosts. Esto minimiza el impacto de un solo objetivo lento en todo el lote.
- **Estrategia de Timeout Optimizada**: Reemplazada la logica de "reintento con timeout extendido" por una estrategia de "division inmediata". Si un lote da timeout, se divide inmediatamente en trozos mas pequeños en lugar de reintentarse, evitando tiempo perdido.

## Corregido

- **Bucle de Reintento Infinito**: Corregido un bug donde los reintentos anidados heredaban el reinicio del contador `retry_attempt`, causando que los lotes se reintentaran indefinidamente si seguian dando timeout.
- **Formato ETA**: Corregida una regresion en la consistencia del simbolo de ETA.

## Pruebas

- Anadido `tests/core/test_nuclei_parallel.py` para verificar la aceleracion por ejecucion concurrente.
- Verificada una aceleracion de ~4x en escaneos simulados de redes grandes (40+ objetivos web).

## Actualizacion

```bash
git pull origin main
```
