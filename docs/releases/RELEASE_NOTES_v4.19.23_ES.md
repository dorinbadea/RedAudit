# RedAudit v4.19.23 - Endurecimiento de seguridad

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.23/docs/releases/RELEASE_NOTES_v4.19.23.md)

## Summary

Endurece la seguridad del transporte en webhooks y sondeos HTTP, y ajusta operaciones locales.

## Added

- None.

## Improved

- Envio de webhooks solo por HTTPS con logs saneados y redirects desactivados.
- El enriquecimiento HTTP verifica TLS primero y solo usa modo inseguro si falla.
- Limpieza de terminal mas segura y permisos restrictivos en temporales de proxy.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.23.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.23/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.23/docs/INDEX.md)
