# RedAudit v4.19.17 - Bootstrap de snap en instalador

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/docs/releases/RELEASE_NOTES_v4.19.17.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/docs/releases/RELEASE_NOTES_v4.19.17_ES.md)

## Summary

Mejora los fallbacks del instalador preparando snapd en sistemas basados en Ubuntu para que searchsploit y ZAP se instalen cuando apt no ofrece paquetes.

## Added

- None.

## Improved

- Las instalaciones vía snap ahora funcionan en sistemas basados en Ubuntu sin snapd preinstalado.

## Fixed

- searchsploit y ZAP ahora se instalan de forma más fiable en derivados de Ubuntu cuando apt no tiene paquetes.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.17.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/docs/INDEX.md)
