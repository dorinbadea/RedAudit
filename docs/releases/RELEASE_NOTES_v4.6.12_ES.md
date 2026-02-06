[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.12/docs/releases/RELEASE_NOTES_v4.6.12.md)

# RedAudit v4.6.12 - Progreso Intra-batch de Nuclei

## Summary

- Añade avance basado en tiempo dentro de cada batch de Nuclei para evitar barras congeladas en ejecuciones largas.

## Added

- None.

## Improved

- Los batches de Nuclei ahora muestran progreso con tiempo transcurrido dentro del batch, manteniendo el cierre por batch.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
