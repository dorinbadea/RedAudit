# Notas de Lanzamiento RedAudit v4.6.27

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.27/docs/releases/RELEASE_NOTES_v4.6.27.md)

## Resumen

**RedAudit v4.6.27** resuelve el cuello de botella en la fase **HyperScan-First** que causaba que los escaneos tardaran ~1 minuto por host en lugar de segundos.

## Corregido

- **Lógica de Throttling HyperScan**:
  - **Comportamiento Anterior**: El escáner trataba "Conexión Rechazada" (puertos cerrados) igual que "Tiempo de Espera Agotado" (Timeout). El controlador de velocidad adaptativo (SmartThrottle) interpretaba esto como una pérdida de paquetes del 99%, forzando la velocidad al mínimo seguro (100 puertos/lote).
  - **Nuevo Comportamiento**: Distingue explícitamente entre `RST` (Puerto Cerrado) y `Timeout`. Los puertos cerrados ahora se cuentan correctamente como sondeos de red exitosos.
  - **Impacto**: El escáner ahora identifica correctamente la estabilidad de la red y acelera hasta 20.000 puertos/lote, reduciendo barridos completos (1-65535) de ~60s a ~3s por host.

## Actualización

```bash
git pull origin main
```
