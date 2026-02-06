# Notas de la Versión v4.13.2

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.13.2/docs/releases/RELEASE_NOTES_v4.13.2.md)

**Fecha de Lanzamiento:** 2026-01-18

## Resumen

Esta versión se centra en **mejoras de calidad de los resultados de escaneo**, asegurando que los informes HTML muestren detalles técnicos completos y que los falsos positivos se filtren correctamente.

## Corregido

- **Referencias en Informe HTML**: Corregido mismatch de claves (`reference` vs `references`) que causaba "Sin detalles técnicos adicionales" en la sección de Hallazgos. Nuclei genera la clave `reference`, pero el generador HTML buscaba `references`.

- **Falso Positivo CVE-2022-26143**: Mejorada la detección de FRITZ!OS para incluir los primeros 2000 caracteres del cuerpo de la respuesta, no solo la cabecera Server. Esto evita que vulnerabilidades de Mitel MiCollab se reporten incorrectamente en dispositivos FRITZ!Box/FRITZ!OS.

- **Extracción de Datos Enriquecidos de Nuclei**: Ahora se extraen campos adicionales de los hallazgos de Nuclei:
  - `impact` - Descripción del impacto potencial del ataque
  - `remediation` - Pasos recomendados para la corrección
  - `cvss_score` - Puntuación CVSS (0.0-10.0)
  - `cvss_metrics` - Vector CVSS completo
  - `extracted_results` - Datos extraídos por Nuclei de las respuestas

- **Fallback de Observaciones Vacías**: Añadida lógica de fallback para usar la descripción de la vulnerabilidad cuando `parsed_observations` está vacío, asegurando que los hallazgos siempre muestren detalles técnicos significativos.

- **Atribución de Fuente**: Cambiada la fuente por defecto de `unknown` a `redaudit` para hallazgos auto-generados (ej: descubrimientos de servicios HTTP). Añadida detección de WhatWeb en la cadena de atribución de fuente.

## Testing

- Todos los cambios incluyen tests unitarios
- 1919 tests pasados, 1 omitido
- Pre-commit hooks pasados (black, flake8, bandit, mypy)

## Actualización

```bash
git pull origin main
pip install -e .
```

O reinstalar:

```bash
sudo bash redaudit_install.sh
```
