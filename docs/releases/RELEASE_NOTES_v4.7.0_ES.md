# Notas de la Version - v4.7.0

**Fecha de lanzamiento**: 2026-01-15

## Resumen

Esta version introduce la **Integracion de Masscan en HyperScan**, mejorando dramaticamente la velocidad de descubrimiento de puertos de aproximadamente 30 minutos a menos de 10 segundos para redes tipicas.

## Nuevas Funcionalidades

### Integracion de Masscan en HyperScan

Un nuevo modulo `masscan_scanner.py` proporciona descubrimiento rapido de puertos usando masscan como backend principal:

- **`masscan_sweep()`**: Escanea los 10.000 puertos principales en segundos
- **`masscan_batch_sweep()`**: Escaneo eficiente de multiples hosts
- **Fallback automatico**: Si masscan no esta disponible, usa escaneo TCP asyncio
- **Limitacion de tasa**: Usa 1000 paquetes por segundo para evitar saturacion de red

### Mejora de Rendimiento

| Metrica | v4.6.x (scapy) | v4.7.0 (masscan) |
|---------|----------------|------------------|
| Escaneo 36 hosts | ~30 minutos | ~10 segundos |
| Tiempo por host | ~1 minuto | <1 segundo |

## Detalles Tecnicos

La integracion modifica `hyperscan_full_port_sweep()` en `hyperscan.py` para:

1. Verificar si masscan esta disponible (instalado + privilegios root)
2. Usar masscan para el barrido inicial de puertos (1-10000)
3. Revertir a la implementacion asyncio original si masscan falla

## Requisitos

- Masscan debe estar instalado (incluido en `redaudit_install.sh`)
- Se requieren privilegios root para masscan (operacion estandar de RedAudit)

## Notas de Actualizacion

Sin cambios disruptivos. La integracion de masscan es transparente - si masscan no esta disponible, se usa automaticamente el metodo de escaneo anterior.
