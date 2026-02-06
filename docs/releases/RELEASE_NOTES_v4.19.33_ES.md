[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.33/docs/releases/RELEASE_NOTES_v4.19.33.md)

# RedAudit v4.19.33 - Fiabilidad del workflow de releases

## Summary
- El workflow de release ahora actualiza releases existentes y usa notas versionadas, evitando fallos cuando la release ya existe.

## Added
- Ninguno.

## Improved
- Ninguno.

## Fixed
- El job de release usa el archivo de notas del repo y permite actualizar releases existentes.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- Sin accion requerida.
