[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.13/docs/releases/RELEASE_NOTES_v4.6.13.md)

# RedAudit v4.6.13 - Resumen de Objetivos y Feedback de Escaneo

## Summary

- Añade visibilidad clara del alcance antes de ejecutar y mejora el feedback durante fases largas.

## Added

- Resumen de objetivos normalizados en el wizard con hosts estimados.

## Improved

- El progreso de Nuclei sigue el avance por objetivos dentro de cada batch.
- Los timeouts de Nikto aparecen en el detalle de progreso de vulnerabilidades.

## Fixed

- Dispositivos multimedia con servicios Chromecast ya no se clasifican como routers.
- Los títulos de OWASP Juice Shop se resuelven como activos de tipo servidor.
- `run_manifest.json` se marca como parcial cuando hay timeouts en Nuclei.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
