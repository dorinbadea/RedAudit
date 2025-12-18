# RedAudit v3.1.0 - Notas de versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.1.md)

**Fecha de lanzamiento**: 14 de diciembre de 2025
**Tipo**: Release de features - Mejoras SIEM y pipelines de IA
**Versión anterior**: v3.0.4

---

## Visión general

La versión 3.1.0 introduce integración SIEM de nivel enterprise y exportaciones para pipelines de IA. Añade correlación determinística de hallazgos, normalización de severidad, extracción de evidencia estructurada y vistas planas JSONL optimizadas para ingesta tipo streaming.

Esta versión es compatible hacia atrás con v3.0.4 y no requiere pasos de migración. Los campos nuevos son opcionales y las vistas de exportación JSONL/evidencia se omiten cuando el cifrado está activado para evitar artefactos en texto plano.

---

## Novedades en v3.1.0

### 1. Vistas de exportación JSONL (pipelines SIEM/IA)

Cada escaneo puede generar tres ficheros planos en la carpeta de salida (solo cuando el cifrado está desactivado):

- `findings.jsonl`: un hallazgo por línea (ideal para SIEM)
- `assets.jsonl`: un activo por línea (ideal para inventario)
- `summary.json`: resumen compacto para dashboards

### 2. Correlación determinística de hallazgos (`finding_id`)

Los hallazgos incluyen un `finding_id` estable (hash determinístico) basado en:

- activo (`observable_hash`)
- escáner/herramienta
- protocolo/puerto
- firma (CVE/plugin/regla/línea normalizada)
- título normalizado

Esto permite correlación y deduplicación entre escaneos.

### 3. Clasificación por categoría + severidad normalizada

Cada hallazgo se enriquece con:

- `category`: surface/misconfig/crypto/auth/info-leak/vuln
- `severity`: info/low/medium/high/critical
- `severity_score`: numérico 0–100 (orientado a SIEM)
- `normalized_severity`: numérico 0.0–10.0 (estilo CVSS)
- `original_severity`: valor original de la herramienta para trazabilidad

### 4. Observaciones estructuradas + manejo de evidencia

Para herramientas web/TLS (Nikto/TestSSL), RedAudit extrae:

- `parsed_observations`: lista breve estructurada para búsquedas rápidas y resúmenes IA
- `raw_tool_output_sha256`: hash del output raw (integridad/dedup)
- `raw_tool_output_ref`: ruta a output raw externalizado (solo cuando el cifrado está desactivado y el output es grande)

### 5. Proveniencia de herramientas (`scanner_versions`)

Los reportes incluyen `scanner_versions`, un mapa best-effort de versiones detectadas (p. ej., nmap/nikto/testssl/whatweb/searchsploit) además de RedAudit.

### 6. Módulos nuevos

```text
redaudit/core/
├── scanner_versions.py  # Detección de versiones de herramientas
├── evidence_parser.py   # Extracción de observaciones Nikto/TestSSL
└── jsonl_exporter.py    # Vistas de exportación JSONL/summary
```

---

## Enlaces útiles

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **Manual de usuario (EN)**: [docs/en/MANUAL.es.md](../MANUAL.es.md)
- **Manual (ES)**: [docs/es/MANUAL.es.md](../MANUAL.es.md)
- **Esquema de reporte (EN)**: [docs/en/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
- **Esquema de reporte (ES)**: [docs/es/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
- **Especificación de seguridad**: [EN](../SECURITY.es.md) / [ES](../SECURITY.es.md)
