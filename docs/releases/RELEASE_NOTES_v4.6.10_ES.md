[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.10/docs/releases/RELEASE_NOTES_v4.6.10.md)

# RedAudit v4.6.10 - Entrada de objetivos flexible

## Summary

- El wizard y la CLI aceptan objetivos CIDR/IP/rango separados por comas con normalizacion.

## Added

- La entrada manual del wizard acepta listas CIDR/IP/rango y expande rangos a bloques CIDR.
- El parseo de objetivos en CLI acepta rangos IP y normaliza IPs individuales a /32.

## Improved

- Roadmap sin emojis y reordenado cronologicamente.
- README/uso/manual actualizados para reflejar formatos de objetivos.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
