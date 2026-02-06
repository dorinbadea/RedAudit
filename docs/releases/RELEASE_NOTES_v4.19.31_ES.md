[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.31/docs/releases/RELEASE_NOTES_v4.19.31.md)

# RedAudit v4.19.31 - OUI en el instalador y señales de confianza

## Summary
- El instalador deja una base OUI de Wireshark para identificar vendors desde el primer arranque.
- Las señales experimentales de TestSSL se tratan como baja confianza y se muestran como posibles falsos positivos.

## Added
- Provision automatica de la base OUI en `~/.redaudit/manuf` durante la instalacion.

## Improved
- La remediacion prioriza el tipo de dispositivo y sus pistas frente a listas de vendors.
- Overrides de OUI via config, variables de entorno y auto-descubrimiento en `~/.redaudit/`.

## Fixed
- Los hallazgos experimentales de TestSSL ya no se tratan como explotables confirmados.
- Los informes HTML muestran posibles falsos positivos junto a observaciones tecnicas.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No requiere accion.
