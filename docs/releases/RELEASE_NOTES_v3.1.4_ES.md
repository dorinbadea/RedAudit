# RedAudit v3.1.4 - Notas de versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.1.4.md)

**Fecha de lanzamiento**: 15 de Diciembre de 2025
**Enfoque**: Mejoras de Calidad de Salida para Máximo Scoring SIEM/IA

---

## Resumen

La versión 3.1.4 aborda problemas de calidad de salida identificados durante el análisis de escaneos. El objetivo principal es maximizar la utilidad de los hallazgos de RedAudit para ingesta SIEM y pipelines de análisis de IA, mejorando la claridad de títulos, reduciendo falsos positivos y añadiendo metadatos contextuales.

---

## Novedades en v3.1.4

### Títulos Descriptivos de Hallazgos

**Antes**: Títulos genéricos como `"Hallazgo en http://192.168.1.1:80/"`
**Después**: Títulos contextuales como `"Cabecera X-Frame-Options Faltante (Riesgo de Clickjacking)"`

La función `_extract_title()` en `jsonl_exporter.py` ahora analiza las observaciones para generar títulos significativos:

- Problemas de cabeceras de seguridad → "Cabecera HSTS Faltante", "Falta X-Content-Type-Options"
- Problemas SSL/TLS → "Desajuste de Hostname en Certificado SSL", "Certificado SSL Expirado"
- Referencias CVE → "Vulnerabilidad Conocida: CVE-2023-12345"
- Divulgación de información → "Dirección IP Interna Divulgada en Cabeceras"

### Cross-Validación Nikto

Nueva función `detect_nikto_false_positives()` que compara hallazgos de Nikto con cabeceras HTTP capturadas por `curl` y `wget`:

```json
{
  "nikto_findings": ["The X-Content-Type-Options header is not set."],
  "curl_headers": "X-Content-Type-Options: nosniff\r\n...",
  "potential_false_positives": [
    "X-Content-Type-Options: Cabecera presente en respuesta pero Nikto la reporta ausente"
  ]
}
```

Esto ayuda a los analistas a identificar rápidamente contradicciones y priorizar la investigación.

### Ajuste de Severidad RFC-1918

Las divulgaciones de IP interna en redes privadas ahora se califican correctamente:

- **Antes**: `{"severity": "high", "severity_score": 70}` (incorrectamente alto)
- **Después**: `{"severity": "low", "severity_score": 30, "severity_note": "Divulgación RFC-1918 en red privada (severidad reducida)"}`

El helper `is_rfc1918_address()` detecta cuando el host objetivo está en espacio RFC-1918 (10.x, 172.16-31.x, 192.168.x).

### Extracción de Fingerprint de SO

Nueva función `extract_os_detection()` que parsea la salida de Nmap para extraer info de SO estructurada:

```python
extract_os_detection("OS details: Linux 5.4 - 5.11")  # Devuelve "Linux 5.4 - 5.11"
extract_os_detection("Running: Microsoft Windows 10")  # Devuelve "Microsoft Windows 10"
```

### Rutas PCAP Relativas

Las referencias a archivos PCAP ahora son portables:

```json
{
  "pcap_file": "traffic_192.168.1.1.pcap",
  "pcap_file_abs": "/root/Documents/RedAuditReports/RedAudit_2025-12-15/traffic_192.168.1.1.pcap"
}
```

Los informes pueden moverse entre sistemas sin romper las referencias a archivos.

### Timeout TestSSL Configurable

La función `ssl_deep_analysis()` ahora acepta un timeout configurable:

```python
ssl_deep_analysis(host_ip, port, extra_tools, timeout=120)  # Timeout extendido
```

Por defecto aumentado de 60s a 90s para acomodar configuraciones SSL complejas.

### Constante de Versión de Schema

Nueva constante `SCHEMA_VERSION` en `constants.py` separa el versionado del schema de informes del versionado de la aplicación:

```python
VERSION = "3.1.4"        # Versión de aplicación
SCHEMA_VERSION = "3.1"   # Versión de schema de informes
```

---

## Archivos Modificados

| Archivo | Cambios |
|---------|---------|
| `redaudit/core/jsonl_exporter.py` | `_extract_title()` mejorado con 10+ patrones |
| `redaudit/core/scanner.py` | Añadido `extract_os_detection()`, rutas PCAP relativas, timeout configurable |
| `redaudit/core/siem.py` | Añadido `is_rfc1918_address()`, `detect_nikto_false_positives()`, ajuste de severidad |
| `redaudit/utils/constants.py` | Añadida constante `SCHEMA_VERSION` |

---

## Nuevos Campos en Informes

| Campo | Ubicación | Descripción |
|-------|-----------|-------------|
| `severity_note` | Hallazgo | Explicación cuando la severidad fue ajustada |
| `potential_false_positives` | Hallazgo | Array de contradicciones detectadas |
| `pcap_file` | Captura PCAP | Nombre de archivo relativo (portable) |
| `pcap_file_abs` | Captura PCAP | Ruta absoluta (uso interno) |

---

## Notas de Actualización

- **Retrocompatible**: Todos los cambios son aditivos; los pipelines existentes seguirán funcionando
- **No requiere migración**: Los nuevos campos son opcionales y solo aparecen cuando son relevantes
- **Acción recomendada**: Actualizar parsers SIEM para utilizar `potential_false_positives` en triage

---

## Pruebas

```bash
# Verificar versión
redaudit --version  # Debe mostrar: RedAudit v3.1.4

# Ejecutar escaneo y verificar nuevos campos
sudo redaudit --target 192.168.1.0/24 --mode normal --yes
jq '.hosts[].vulnerabilities[] | select(.potential_false_positives)' report.json
```
