[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.5/docs/releases/RELEASE_NOTES_v4.6.5.md)

## Resumen

Refuerza el flujo de actualización para que la versión reportada sea consistente incluso con tags o instalaciones locales incoherentes. El updater fuerza el `VERSION` objetivo, evita actualizaciones parciales del sistema sin sudo y el banner prioriza el archivo `VERSION` empaquetado.

## Añadido

- Ninguno.

## Mejoras

- El flujo de actualización bloquea las actualizaciones del sistema sin sudo cuando se ejecuta `/usr/local/bin/redaudit` para evitar instalaciones parciales.

## Corregido

- El updater fuerza el archivo `VERSION` empaquetado para que coincida con el tag objetivo durante la actualización.
- La resolución de versión prioriza el archivo `VERSION` empaquetado frente a la metadata instalada para evitar banners obsoletos.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualización

```bash
git pull origin main
```
