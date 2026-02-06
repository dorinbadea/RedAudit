# RedAudit v4.18.8 - Anclaje del toolchain en el instalador

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.8/docs/releases/RELEASE_NOTES_v4.18.8.md)

## Summary

Esta version añade un modo de anclaje del toolchain en el instalador, incorpora un lockfile de Poetry para evaluacion y refactoriza el descubrimiento Red Team en un modulo dedicado.

## Added

- Ninguno.

## Improved

- El instalador soporta `REDAUDIT_TOOLCHAIN_MODE=latest` para testssl/kerbrute y overrides de version (`TESTSSL_VERSION`, `KERBRUTE_VERSION`, `RUSTSCAN_VERSION`).
- Añadido `poetry.lock` junto a pip-tools para paridad de workflow y evaluacion.
- La logica de descubrimiento Red Team vive ahora en un modulo dedicado para reducir `net_discovery.py`.

## Fixed

- El instalador de kerbrute ya no reporta "ya instalado" tras una instalacion nueva.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.8 para controlar versiones del toolchain durante la instalacion.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.8/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.18.8/docs/INDEX.md)
