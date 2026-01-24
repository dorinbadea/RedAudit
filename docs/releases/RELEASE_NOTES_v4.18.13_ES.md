# RedAudit v4.18.13 - Exclusiones del auditor y parseo SMB de dominio

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.13/docs/releases/RELEASE_NOTES_v4.18.13.md)

## Summary

Esta version anade metadatos explicitos de exclusiones del auditor en el manifiesto y corrige el parseo SMB de dominio para evitar contaminacion por FQDN en resumenes sin agente.

## Added

- El manifiesto y los resumenes del pipeline incluyen `auditor_exclusions` con IPs excluidas y sus razones.

## Improved

- Ninguno.

## Fixed

- El parseo SMB sin agente ya no arrastra lineas de FQDN cuando el dominio esta vacio.

## Testing

- `pytest tests/core/test_agentless_verify.py -v`
- `pytest tests/core/test_reporter.py -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.13 para mayor transparencia en exclusiones del auditor y pistas SMB corregidas.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.13/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.13/docs/INDEX.md)
