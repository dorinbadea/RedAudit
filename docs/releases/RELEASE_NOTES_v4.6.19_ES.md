[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.19/docs/releases/RELEASE_NOTES_v4.6.19.md)

# RedAudit v4.6.19 - Priorización y Detección de Backdoors

## Resumen

- Añade **Priorización de Hallazgos** y **Puntuación de Confianza** para mejor calidad de reporte.
- Introduce **Detección Clásica de Vulnerabilidades** para backdoors conocidos.
- Mejora **Títulos de Reportes** e **Interfaz Wizard** (visualización de spray count).

## Añadido

- **Priorización de Hallazgos**: Nuevos campos `priority_score` (0-100) y `confirmed_exploitable` para clasificar mejor las vulnerabilidades. Sistema ponderado prioriza CVEs y hallazgos verificados.
- **Detección Clásica de Vulnerabilidades**: Detección automática de servicios con backdoors conocidos (vsftpd 2.3.4, UnrealIRCd 3.2.8.1, Samba, distcc, etc.) basada en análisis de banners.
- **Calidad de Reporte**: Nuevo `confidence_score` (0.0-1.0) para hallazgos basado en señales de verificación (ej. coincidencia de CVE, confirmación de Nuclei).
- **Títulos Mejorados**: Mejor generación de títulos, detectando vulnerabilidades específicas (BEAST, POODLE) y títulos fallback más claros (ej. "HTTP Service Finding").
- **Exportación JSONL**: Añadidos campos de calidad (`confidence_score`, `priority_score`, `confirmed_exploitable`) a la salida JSONL para ingestión por SIEM.

## Mejorado

- **Interfaz Wizard**: El resumen de credenciales ahora muestra el conteo de entradas en listas de spray (ej. `(+5 spray)`).
- **Mapeo de Severidad**: Mapeo refinado para hallazgos genéricos de escáneres para reducir ruido (ej. bajando severidad para revelación de versiones).

## Corregido

- Ninguno.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualización

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
