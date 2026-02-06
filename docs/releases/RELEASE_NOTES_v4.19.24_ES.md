# RedAudit v4.19.24 - Endurecimiento de reportes y limpieza de reanudación

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.24/docs/releases/RELEASE_NOTES_v4.19.24.md)

## Summary

Endurecimiento defensivo de reportes HTML, mejor observabilidad de fallos de chown y documentación para limpieza de reanudaciones de Nuclei.

## Added

- None.

## Improved

- Los reportes HTML incluyen un meta Content-Security-Policy para defense-in-depth.
- El chown best-effort ahora registra debug cuando falla, para facilitar el diagnostico.
- El override por defecto del timeout de Nuclei se centraliza en una constante compartida.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.24.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.24/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.24/docs/INDEX.md)
