[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.15/docs/releases/RELEASE_NOTES_v4.6.15.md)

# RedAudit v4.6.15 - Estabilidad del progreso de Nuclei y consistencia de informes

## Summary

- Estabiliza el progreso de Nuclei para que el recuento de objetivos no retroceda durante reintentos o timeouts.
- Alinea los hosts con la identidad unificada para informes consistentes.

## Added

- None.

## Improved

- El progreso de Nuclei usa recuento de objetivos y mantiene avance monotono durante reintentos/timeouts.

## Fixed

- Los informes de host incluyen `asset_name`, `interfaces` e `interface_count` cuando existen assets unificados.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
