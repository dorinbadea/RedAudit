# RedAudit v4.18.10 - Pistas DHCP y puertos SSH

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.10/docs/releases/RELEASE_NOTES_v4.18.10.md)

## Summary

Este hotfix aclara los timeouts de descubrimiento DHCP y garantiza que los escaneos autenticados apunten a SSH en puertos no estándar.

## Added

- Ninguno.

## Improved

- La guía de troubleshooting explica causas comunes de timeouts DHCP y los siguientes pasos.

## Fixed

- El descubrimiento DHCP añade pistas best-effort cuando el broadcast no responde a tiempo.
- Los escaneos autenticados detectan SSH en puertos no 22 (por ejemplo, 2222).

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.10 para mejorar la guía DHCP y la cobertura SSH autenticada.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.10/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.10/docs/INDEX.md)
