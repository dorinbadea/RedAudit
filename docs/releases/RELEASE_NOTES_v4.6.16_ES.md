[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.16/docs/releases/RELEASE_NOTES_v4.6.16.md)

# RedAudit v4.6.16 - Endurecimiento de timeouts en Nuclei

## Summary

- Reduce ejecuciones parciales de Nuclei con timeouts adaptativos por lote y divisiones recursivas.
- Usa timeout y reintentos por peticion cuando la version instalada de Nuclei lo soporta.

## Added

- None.

## Improved

- La gestion de reintentos y timeouts de Nuclei degrada el tamano del lote para aislar objetivos lentos.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
