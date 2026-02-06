# RedAudit v4.19.18 - Control y claridad de timeouts en Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/docs/releases/RELEASE_NOTES_v4.19.18.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/docs/releases/RELEASE_NOTES_v4.19.18_ES.md)

## Summary

Añade controles de exclusión de objetivos Nuclei y diagnósticos más claros de progreso/timeout en lotes largos.

## Added

- Lista de exclusion de Nuclei (CLI y asistente) para omitir objetivos por host, host:puerto o URL.
- Avisos de timeout con resumen de hosts/puertos del lote bloqueado.

## Improved

- El detalle de progreso muestra reintentos y profundidad de split en lotes de Nuclei.
- Los resúmenes Nuclei incluyen `targets_excluded` para trazabilidad.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.18.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/docs/INDEX.md)
