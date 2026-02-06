[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.30/docs/releases/RELEASE_NOTES_v4.19.30.md)

# RedAudit v4.19.30 - Targets de cobertura total Nuclei

## Summary
- La cobertura total ahora incluye todos los puertos HTTP detectados en hosts con identidad fuerte, alineando el prompt con el comportamiento.

## Added
- Ninguno.

## Improved
- La seleccion de cobertura total de Nuclei ahora coincide con el prompt interactivo para escanear todos los puertos HTTP.

## Fixed
- La seleccion optimizada ya no limita puertos HTTP cuando la cobertura total esta activa.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No requiere accion.
