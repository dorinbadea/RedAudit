# RedAudit v4.18.20 - Resiliencia de Nuclei y ajuste de UI

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.20/docs/releases/RELEASE_NOTES_v4.18.20.md)

## Summary

Esta version estabiliza ejecuciones largas de Nuclei, mantiene coherente el idioma de la UI tras overrides del CLI y mejora el contraste ANSI.

## Added

- None.

## Improved

- Las lineas de estado en ANSI aplican el color al texto completo para un contraste consistente fuera de Rich.

## Fixed

- El UI manager se resincroniza cuando cambia el idioma del CLI tras la inicializacion para evitar mezcla EN/ES.
- Los timeouts largos de Nuclei ahora limitan los lotes paralelos para evitar timeouts del escaneo completo.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v --cov=redaudit --cov-report=term-missing`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.20.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.20/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.20/docs/INDEX.md)
