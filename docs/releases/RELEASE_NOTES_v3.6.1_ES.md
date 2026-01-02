# RedAudit v3.6.1 - Calidad de Escaneo y UX

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.6.1.md)

Fecha de Lanzamiento: 2025-12-18

## Puntos Destacados

- **Consolidación de Hallazgos**: Los hallazgos duplicados en el mismo host (ej: "X-Frame-Options faltante" en 5 puertos) ahora se fusionan en uno con array `affected_ports`.
- **Fallback OUI Online**: Nuevo módulo para consulta de vendor MAC via macvendors.com cuando la base local está incompleta.
- **Detección de Puertos HTTPS**: Ampliada detección SSL/TLS para incluir puertos no estándar (8443, 4443, 9443, 49443).

## Correcciones

- **Integración Nuclei**: Corregido `get_http_targets_from_hosts()` que usaba `state != "open"` pero los puertos de RedAudit no tienen campo `state`. Ahora usa correctamente el flag `is_web_service`.
- **Ruido en Barra de Progreso**: Comando nmap condensado de comando completo a `[nmap] IP (tipo de escaneo)` para display más limpio.
- **Manejo de Falsos Positivos**: Cuando la cross-validación detecta que Nikto reportó una cabecera faltante pero curl/wget la muestra presente, la severidad se degrada a `info` con `verified: false`.

## Cambios

- **Ejecución testssl**: Ahora corre en todos los puertos HTTPS (8443, 49443, etc.), no solo en puerto 443.

## Archivos Modificados

- `redaudit/core/auditor.py` - Integración OUI fallback, limpieza barra progreso
- `redaudit/core/nuclei.py` - Corregida generación de targets
- `redaudit/core/siem.py` - Añadido `consolidate_findings()`, degradación severidad FP
- `redaudit/utils/oui_lookup.py` - Nuevo módulo

## Documentación

- [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
- [Guía de Uso](../USAGE.es.md)
