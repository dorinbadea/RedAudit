[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.44/docs/releases/RELEASE_NOTES_v4.19.44.md)

# RedAudit v4.19.44 - Refresco de estabilidad en runtime de Rich

## Summary

Este parche actualiza dependencias de renderizado en terminal para mejorar la estabilidad en ejecucion y la consistencia de salida.

## Added

- No se anaden funciones nuevas visibles para el usuario en esta version.

## Improved

- Rich se actualiza de 14.2.0 a 14.3.2 para reforzar la resiliencia del renderizado en terminal.

## Fixed

- Los locks de dependencias quedan alineados para que entornos pip/Poetry usen la misma base de Rich.

## Testing

- Validacion interna completada.

## Upgrade

- No requiere accion.
