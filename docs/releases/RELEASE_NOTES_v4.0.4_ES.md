# Notas de la Versión v4.0.4

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.0.4/docs/releases/RELEASE_NOTES_v4.0.4.md)

**Fecha de Publicación:** 2026-01-05

Este hotfix aborda brechas críticas de detección y corrige una regresión visual de la CLI introducida en v4.0.x.

## Destacado

### Corrección de Integración de Puertos HyperScan

Cuando HyperScan detectaba puertos abiertos durante net_discovery pero el escaneo inicial de nmap no encontraba ninguno (debido al umbral de identidad), ahora forzamos un escaneo profundo. Esto corrige la brecha de detección de Metasploitable2 donde 10+ puertos fueron detectados por HyperScan pero ignorados.

### Regresión Visual de CLI Corregida

Restaurada la salida completa de colores y retroalimentación visual:

- `[INFO]` → azul brillante
- `[WARN]` → amarillo brillante
- `[FAIL]` → rojo brillante
- `[OK]` → verde brillante
- Spinner restaurado en la barra de progreso
- La barra de progreso ahora muestra la IP en lugar del objeto `Host(...)` crudo

## Corregido

- **Crítico: Integración de Puertos HyperScan**: Forzar escaneo profundo cuando HyperScan detecta puertos pero nmap no encuentra ninguno
- **Brecha en Detección de Vulnerabilidades**: Hosts con huellas HTTP ahora activan correctamente el escaneo de vulnerabilidades web
- **Detección Web Basada en Puertos**: Añadida constante `WEB_LIKELY_PORTS` para puertos web comunes (3000, 8080, etc.)
- **Selección de Hosts para Escaneo de Vulns**: Mejor selección de hosts para escaneo de vulnerabilidades
- **Precisión del Resumen Agentless**: Corregido el conteo de señales HTTP
- **Prioridad de Títulos Descriptivos**: Los problemas SSL/TLS ahora tienen prioridad sobre fugas de información menores
- **Regresión Visual de CLI**: Cambiado de markup Rich a objetos `rich.text.Text`
- **Visualización de Barra de Progreso**: Ahora muestra la IP limpia en lugar de `Host(ip='...')`
- **Spinner Restaurado**: Re-añadido `SpinnerColumn` para retroalimentación visual
- **Sincronización de Estado UIManager**: Añadido `progress_active_callback` para colores consistentes

## Cambiado

- **Lógica de Escaneo Profundo**: Usa puertos HyperScan como señal (`hyperscan_ports_detected`)
- **Fallback HyperScan**: Cuando nmap hace timeout, poblar puertos desde datos de HyperScan
- **Colores Rich**: Actualizado a variantes `bright_*` para mejor visibilidad en temas oscuros

## Actualización

```bash
git pull origin main
sudo bash redaudit_install.sh
```

## Verificación

Ejecuta un escaneo para verificar las correcciones:

```bash
sudo redaudit --target <tu-red> --mode full --nuclei --yes
```

Deberías ver:

- Salida con todos los colores para mensajes de estado
- Animación de spinner en la barra de progreso
- Escaneo profundo activado para hosts con puertos detectados por HyperScan
