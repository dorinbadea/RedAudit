# RedAudit v4.18.5 - Seguridad de Deep Scan y estabilidad de HyperScan

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.5/docs/releases/RELEASE_NOTES_v4.18.5.md)

## Resumen

Esta versión corrige el truncamiento en Deep Scan y limita los lotes de HyperScan para evitar agotamiento de descriptores.

## Añadido

- Ninguno.

## Mejorado

- Ninguno.

## Corregido

- Deep Scan ahora captura stdout completo para evitar perder puertos en ejecuciones Nmap verbosas.
- El tamaño de lote TCP de HyperScan ahora se limita al 80% del soft limit de FD para evitar `Too many open files`.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualizar

- Sin pasos especiales. Actualiza y ejecuta como siempre.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.5/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.5/docs/INDEX.md)
