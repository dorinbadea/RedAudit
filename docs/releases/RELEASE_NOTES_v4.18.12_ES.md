# RedAudit v4.18.12 - Métricas HyperScan y claridad DHCP

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.12/docs/releases/RELEASE_NOTES_v4.18.12.md)

## Summary

Esta versión corrige las métricas de HyperScan-First, refina las pistas de timeouts DHCP y mejora la claridad de informes en español.

## Added

- Ninguno.

## Improved

- Ninguno.

## Fixed

- HyperScan-First ahora gobierna las comparativas `hyperscan_vs_final` para evitar subcuentas de puertos en el discovery rápido.
- HyperScan-First fusiona puertos de masscan como fallback en lugar de reemplazar los resultados de RustScan.
- Los timeouts DHCP ya no indican falta de IPv4 cuando existe dirección de origen en la ruta por defecto.
- Los informes HTML en español traducen los errores del escaneo autenticado.
- La exclusión de IPs del auditor considera IPs locales de interfaces y rutas.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.18.12 para métricas de HyperScan más precisas y mensajes DHCP/informes más claros.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.12/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.12/docs/INDEX.md)
