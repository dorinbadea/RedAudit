# Notas de Versión v3.8.8

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.8.md)

**Fecha de lanzamiento**: 2025-12-25

## Aspectos Destacados

Esta versión introduce **Fingerprinting HTTP de Dispositivos** para identificar automáticamente dispositivos de red desde los títulos de su interfaz web, y corrige el problema de ruido en la salida CLI para logs de captura de terminal más limpios.

## Novedades

### Fingerprinting HTTP de Dispositivos

RedAudit ahora identifica automáticamente vendors y modelos de dispositivos analizando headers HTTP title y server durante la verificación agentless. Especialmente útil para:

- **Routers**: Vodafone, FRITZ!Box, TP-Link, NETGEAR, ASUS, Linksys, D-Link, Ubiquiti, MikroTik, Huawei, ZTE, DrayTek
- **Switches**: Cisco, HPE/Aruba, Juniper
- **Cámaras**: Hikvision, Dahua, Axis, Reolink, ONVIF
- **IoT/Smart Home**: Philips Hue, Home Assistant, Tasmota, Shelly, Sonoff
- **NAS**: Synology, QNAP
- **Impresoras**: HP, Epson, Brother, Canon
- **Servidores**: VMware ESXi, Proxmox, iLO/iDRAC

Nuevos campos en la salida de fingerprint agentless:

- `device_vendor`: Fabricante identificado
- `device_model`: Cadena del modelo específico
- `device_type`: Categoría (router, switch, camera, iot, nas, printer, server, etc.)

### Corrección de Ruido en Salida CLI

Frecuencia de actualización de barras de progreso Rich reducida de 10Hz a 4Hz en las 9 barras de progreso. Esto previene archivos de log excesivamente grandes cuando la salida del terminal se captura externamente (ej. usando el comando `script`).

**Antes**: ~479KB cli.txt con frames de spinner repetidos
**Después**: ~20KB cli.txt limpio coincidiendo con el log de sesión interno

## Archivos Modificados

- `redaudit/core/agentless_verify.py` - Añadido `_HTTP_DEVICE_PATTERNS` y `_fingerprint_device_from_http()`
- `redaudit/core/auditor.py` - Añadido `refresh_per_second=4` a 3 barras de progreso
- `redaudit/core/auditor_scan.py` - Añadido `refresh_per_second=4` a 3 barras de progreso
- `redaudit/core/auditor_vuln.py` - Añadido `refresh_per_second=4` a 1 barra de progreso
- `redaudit/core/hyperscan.py` - Añadido `refresh_per_second=4` a 1 barra de progreso
- `redaudit/core/nuclei.py` - Añadido `refresh_per_second=4` a 1 barra de progreso

## Actualización

```bash
redaudit --version  # Verificar versión actual
# Si auto-update está habilitado, RedAudit pedirá actualizar
# O manualmente: curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/main/redaudit_install.sh | sudo bash
```

## Changelog Completo

Ver [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md) para la lista completa de cambios.
