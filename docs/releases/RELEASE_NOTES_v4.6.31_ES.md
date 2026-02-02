# v4.6.31: HyperScan Velocity (Hotfix)

**Fecha:** 15-01-2026

Solucionado un cuello de botella en la fase **HyperScan-First** donde los hosts se escaneaban secuencialmente, causando retrasos significativos.

##  Rendimiento

- **HyperScan Paralelo**: Ahora ejecuta hasta **8 hosts simultáneamente** en la fase de pre-escaneo (antes secuencial).
- **Batching Adaptativo**: Calcula automáticamente el tamaño de lote (`batch_size`) seguro basado en el límite de Descriptores de Archivo del sistema (`ulimit -n`) para maximizar velocidad sin errores.

## ️ Correcciones

- **Seguridad FD**: Previene errores de `Too many open files` escalando la concurrencia dinámicamente.
