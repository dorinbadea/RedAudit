# Notas de la Versión v4.6.33 - Rendimiento, Precisión y Localización

**Fecha**: 15-01-2026
**Versión**: 4.6.33

Esta versión hotfix soluciona cuellos de botella críticos en Net Discovery, mejora la precisión de HyperScan y refina la localización al español.

##  Mejoras Clave

### ⚡ Optimización de Net Discovery

- **Timeouts de Protocolo más Rápidos**: Se han reducido los timeouts por defecto para protocolos bloqueantes (Fping, NetBIOS, ARP) de **30s** a **15s**. Esto resuelve casos donde Net Discovery podía colgarse durante 10-12 minutos en redes complejas o no responsivas.
- **Registro de Depuración Granular**: Añadidos logs de debug detallados (`NetDiscovery: Starting {proto}`) para identificar protocolos específicos que se atascan en tiempo real.

###  Precisión de HyperScan

- **Aumento de Timeout**: El timeout de `HyperScan-First` se ha incrementado de **0.5s** a **1.5s**. Esto evita falsos negativos (reportar 0 puertos) en hosts con ligera latencia o alta carga.
- **Logging Paralelo**: Corregidos mensajes de log engañosos que indicaban ejecución "secuencial" cuando realmente se ejecutaba en paralelo.
- **Estabilidad Paralela**: Corregido un bug crítico de condición de carrera en `HyperScan-First` que podía sobrescribir resultados de hosts al usar variables de bucle estale.

###  Localización (Español)

- **Estándares de Español de España**: Términos estandarizados para la región (`es_ES`):
  - Cambiado "Archivo" a "Fichero".
  - Estandarizada la terminología "Net Discovery" en el Asistente.
  - Añadida traducción faltante para "UDP probes" -> "Sondas UDP".
- **Corrección de Erratas**: Corregido el error tipográfico "secuencialmente" en el mensaje de inicio de HyperScan.

##  Cambios

- `redaudit/utils/i18n.py`: Traducciones actualizadas.
- `redaudit/core/hyperscan.py`: Aumentado timeout y añadido soporte de localización.
- `redaudit/core/net_discovery.py`: Timeouts optimizados y logging añadido.

---
**Actualización**: `git pull && sudo pip3 install .`
