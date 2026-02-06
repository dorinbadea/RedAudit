[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.40/docs/releases/RELEASE_NOTES_v4.19.40.md)

# RedAudit v4.19.40 - Alineacion de consistencia y evidencia de riesgo

## Summary

Este parche mejora la consistencia en reanudaciones y alinea los resumenes de severidad con la evidencia de riesgo que ya utiliza el calculo de riesgo por host.

## Added

- `summary.json` incluye ahora:
  - `risk_evidence_severity_breakdown`
  - `combined_severity_breakdown`
  - `total_risk_evidence_findings`
  - `total_findings_with_risk_evidence`

## Improved

- Los hallazgos experimentales de TestSSL reciben un tratamiento de confianza mas estricto cuando coinciden con señales de "no web server found".
- La documentacion del esquema de informe (EN/ES) ahora describe los nuevos campos de evidencia de riesgo en el resumen.

## Fixed

- El enriquecimiento de severidad ahora es idempotente para hallazgos ya normalizados, evitando deriva de riesgo en reanudaciones con hallazgos informativos.
- Las exportaciones de resumen ahora muestran contadores de severidad por evidencia de riesgo basada en CVEs/exploits/firmas de backdoor en puertos de host.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Actualiza a `v4.19.40` desde el repositorio oficial.
2. Ejecuta un escaneo y verifica que `summary.json` incluya las nuevas claves de evidencia de riesgo.
3. Confirma que las reanudaciones mantienen estable el riesgo de host cuando no se agregan hallazgos nuevos.
