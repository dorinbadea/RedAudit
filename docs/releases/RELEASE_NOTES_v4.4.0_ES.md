# RedAudit v4.4.0 - Escalabilidad Enterprise y Smart-Throttle

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v4.4.0.md)

Esta versión introduce mejoras mayores de escalabilidad y limitación de velocidad adaptativa, permitiendo a RedAudit escanear redes masivas (ej. subredes /16) sin agotamiento de memoria ni congestión de red.

## Nuevas Características

### Smart-Throttle (Control de Congestión Adaptativo)

RedAudit ahora "siente" la red. En lugar de un tamaño de lote estático, el nuevo motor **AIMD (Additive Increase, Multiplicative Decrease)** ajusta dinámicamente la velocidad de escaneo:

- **Congestión Detectada**: Si hay pérdida de paquetes o timeouts, RedAudit frena inmediatamente para preservar la precisión.
- **Red Estable**: Si el enlace es saludable, acelera para maximizar el rendimiento.
- **Visual Feedback**: La barra de progreso CLI ahora indica el estado de regulación en tiempo real (ej. `[▼25]` frenando, `[▲100]` acelerando).

### Targeting basado en Generadores

Hemos reescrito la lógica de expansión de objetivos para usar **evaluación perezosa** (generadores) en lugar de listas en memoria.

- **Problema Resuelto**: Escanear una `/16` requería generar 65k+ objetos IP en memoria antes de empezar.
- **Solución**: Los objetivos ahora se generan bajo demanda.
- **Efecto**: El uso de memoria permanece plano y mínimo (<100MB) incluso escaneando millones de objetivos.

### Arquitectura Preparada para el Futuro

- **Diseño Distribuido**: Añadido `docs/design/distributed_scanning.md` detallando la próxima arquitectura Coordinador/Trabajador para escaneo multi-nodo.
- **Ruta Migración AsyncIO**: Añadido `docs/design/asyncio_migration.md` delineando la hoja de ruta para una reescritura completa a I/O no bloqueante en v5.0.

## Mejoras

- **Optimización de Memoria en Informes**: Refactorizado `_collect_discovery_hosts` para filtrar y procesar hosts más eficientemente durante escaneos grandes.
- **Ajustes UI**: Mejorada la estabilidad de la barra de progreso para evitar que mensajes de "latido" rompan el diseño visual.
- **Experiencia de Desarrollador**: Añadido `requirements.lock` e instrucciones para instalación reproducible basada en pip.

## Correcciones

- Corregido bug de UI donde mensajes de estado se duplicaban en nuevas líneas durante escaneos profundos.
- Corregida indentación en `hyperscan.py` que causaba potenciales problemas lógicos en manejo de conexiones.

## Actualización

```bash
cd RedAudit
git pull origin main
# No hay dependencias nuevas críticas, pero buena práctica:
pip install -r requirements.txt
```
