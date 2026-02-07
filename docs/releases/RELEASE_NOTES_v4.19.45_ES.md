[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.45/docs/releases/RELEASE_NOTES_v4.19.45.md)

# RedAudit v4.19.45 - Aviso inmediato de actualizacion al iniciar

## Summary

Este parche mejora la deteccion de actualizaciones al arrancar para que los usuarios vean nuevas versiones en cuanto abren RedAudit.

## Added

- No se anaden nuevas funciones visibles para el usuario en esta version.

## Improved

- La comprobacion de actualizaciones al iniciar ahora se ejecuta en cada arranque (sin bloqueo y con timeout corto).

## Fixed

- Si no hay conectividad durante la comprobacion de inicio, RedAudit usa la cache de releases como fallback.

## Testing

- Validacion interna completada.

## Upgrade

- No requiere accion.
