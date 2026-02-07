[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.43/docs/releases/RELEASE_NOTES_v4.19.43.md)

# RedAudit v4.19.43 - Optimizacion UX del chequeo de actualizaciones al inicio

## Summary

Este parche mejora la experiencia del chequeo de actualizaciones haciendo la comprobacion de inicio automatica, ligera y no bloqueante.

## Added

- El chequeo de actualizaciones al inicio ahora usa metadatos en cache para reducir llamadas de red repetidas.

## Improved

- RedAudit ahora comprueba actualizaciones automaticamente al arrancar y solo notifica cuando hay una version mas nueva.
- El chequeo al inicio usa timeout corto y mantiene el flujo del escaneo responsivo.

## Fixed

- El comportamiento de chequeo al inicio ahora es consistente entre modos de lanzamiento y respeta `--skip-update-check`.

## Testing

- Validacion interna completada.

## Upgrade

- No action required.
