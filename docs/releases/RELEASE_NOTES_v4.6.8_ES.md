[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.8/docs/releases/RELEASE_NOTES_v4.6.8.md)

## Resumen

Estabiliza las barras de progreso de vulnerabilidades tras finalizar cada host y asegura el tag `web` cuando hay puertos web detectados.

## Añadido

- Ninguno.

## Mejoras

- Ninguna.

## Corregido

- Las barras de progreso de vulnerabilidades dejan de actualizarse tras finalizar un host.
- Los activos web reciben el tag `web` cuando existe `web_ports_count`.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualización

```bash
git pull origin main
```
