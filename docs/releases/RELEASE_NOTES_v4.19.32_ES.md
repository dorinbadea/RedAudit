[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.32/docs/releases/RELEASE_NOTES_v4.19.32.md)

# RedAudit v4.19.32 - Correccion ShellCheck del instalador

## Summary
- El instalador define el helper de OUI antes de usarse, manteniendo ShellCheck limpio y el auto-instalado fiable.

## Added
- Ninguno.

## Improved
- Ninguno.

## Fixed
- Se corrige el SC2218 de ShellCheck moviendo la definicion del helper de OUI por encima de su uso.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- Sin accion requerida.
