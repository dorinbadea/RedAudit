# Notas de Versión v4.3.0

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v4.3.0.md)

**Fecha de Lanzamiento**: 2026-01-07
**Tipo**: Lanzamiento de Funcionalidades

## Novedades Destacadas

### 🚀 Modo SYN de HyperScan

Escaneo opcional de puertos basado en SYN usando scapy para **~10x más velocidad** en redes grandes.

- **Flag CLI**: `--hyperscan-mode auto|connect|syn`
- **Modo Auto**: Intenta escaneo SYN si se ejecuta como root con scapy instalado, sino usa TCP connect
- **Modo Connect**: TCP connect estándar (no requiere root, más sigiloso para entornos con IDS)
- **Modo SYN**: Escaneo con paquetes raw (requiere root + scapy, opción más rápida)

**Integración en el Asistente**: Todos los perfiles ahora soportan selección de modo:

- Express: `auto` (más rápido por defecto)
- Estándar/Exhaustivo con timing Sigiloso: `connect` (evasión de IDS)
- Estándar/Exhaustivo con timing Normal/Agresivo: `auto`
- Personalizado: Elección explícita en el Paso 2

### 📊 Tooltip de Desglose de Risk Score

Los reportes HTML ahora muestran los componentes detallados del risk score al pasar el ratón:

- Puntuación CVSS Máxima
- Cálculo de Puntuación Base
- Bonus de Densidad (por múltiples vulnerabilidades)
- Multiplicador de Exposición (por puertos expuestos externamente)

### 🎯 Visualización de Identity Score

Los reportes HTML muestran `identity_score` con código de colores:

- 🟢 Verde (≥3): Host bien identificado
- 🟡 Amarillo (=2): Parcialmente identificado
- 🔴 Rojo (<2): Identificación débil (disparó deep scan)

El tooltip muestra señales de identidad (hostname, vendor, MAC, etc.)

### 🔍 Validación CPE de Smart-Check

Detección mejorada de falsos positivos de Nuclei usando datos CPE:

- Nuevas funciones: `parse_cpe_components()`, `validate_cpe_against_template()`, `extract_host_cpes()`
- Valida hallazgos contra CPEs del host antes de comprobaciones de cabeceras HTTP
- Reduce falsos positivos cuando el CPE no coincide con el vendor esperado

### 📁 Utilidades de Gestión de PCAP

Nuevas utilidades para organización de archivos PCAP:

- `merge_pcap_files()`: Consolida archivos de captura usando `mergecap`
- `organize_pcap_files()`: Mueve capturas raw a subdirectorio
- `finalize_pcap_artifacts()`: Orquesta limpieza post-escaneo

## Cambios Incompatibles

Ninguno. Esta versión es totalmente compatible hacia atrás.

## Nuevas Opciones CLI

| Flag | Descripción |
|------|-------------|
| `--hyperscan-mode` | Método de descubrimiento HyperScan: `auto`, `connect` o `syn` |

## Nuevos Archivos

- `redaudit/core/syn_scanner.py` — Módulo de escáner SYN basado en scapy

## Dependencias

**Opcional** (para modo SYN):

- `scapy` — Instalar con `pip install scapy` o `apt install python3-scapy`

## Instrucciones de Actualización

```bash
# Actualización estándar vía auto-update
redaudit --check-update

# O reinstalación manual
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/main/redaudit_install.sh | sudo bash
```

## Notas de Prueba

- El modo SYN requiere privilegios de root (`sudo redaudit`)
- Probar en Ubuntu/Debian con scapy instalado para funcionalidad completa
- El fallback a modo connect funciona sin problemas cuando SYN no está disponible

## Contribuidores

- Dorin Badea ([@dorinbadea](https://github.com/dorinbadea))
