[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.28/docs/releases/RELEASE_NOTES_v4.19.28.md)

# RedAudit v4.19.28 - Reportes HTML e Higiene de Documentacion

## Summary
- Se entrega Chart.js localmente en reportes HTML para que los graficos rendericen con CSP.
- Se actualiza README con arquitectura/toolchain y se alinea el aviso de Nuclei.
- Se eliminan emojis de notas historicas para cumplir el estilo.

## Added
- Ninguno.

## Improved
- Fiabilidad de reportes HTML con Chart.js local.
- Precision de README en arquitectura y toolchain.
- Cumplimiento de estilo en documentacion (sin emojis).

## Fixed
- Renderizado de graficos HTML bloqueado por CSP al usar el CDN.

## Testing
- pre-commit run --all-files
- pytest tests/ -v

## Upgrade
- Actualizacion estandar; sin cambios incompatibles.
