# Notas de Lanzamiento RedAudit v4.6.28

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.28/docs/releases/RELEASE_NOTES_v4.6.28.md)

## Resumen

**RedAudit v4.6.28** soluciona un problema de estabilidad **CRÍTICO** descubierto durante una auditoría de rendimiento. Elimina la "Contaminación Global de Timeout de Sockets", que afectaba la fiabilidad de todos los módulos paralelos (Nuclei, SSH, HTTP).

## Corregido

- **Contaminación Global de Timeout**:
  - **Comportamiento Anterior**: La función `reverse_dns` utilizaba `socket.setdefaulttimeout(timeout)` para forzar un tiempo límite en las búsquedas DNS. Dado que `setdefaulttimeout` afecta al **proceso global de Python**, esto cambiaba inadvertidamente el timeout por defecto para **todos los demás hilos** que se ejecutaban simultáneamente.
  - **Impacto**: Si una búsqueda DNS ocurría mientras se iniciaba un lote de Nuclei o un spray SSH, esas conexiones heredaban el timeout de DNS (ej. 2 segundos) en lugar de su timeout previsto. Esto explica timeouts esporádicos y fallos de conexión en escaneos por lo demás saludables.
  - **Nuevo Comportamiento**: Las búsquedas DNS ahora usan `ThreadPoolExecutor` con timeouts gestionados, asegurando **CERO** efectos secundarios en el estado global de los sockets.

## Actualización

```bash
git pull origin main
```
