[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.7/docs/releases/RELEASE_NOTES_v4.6.7.md)

## Resumen

Evita consultas de credenciales durante el escaneo de puertos cuando la autenticación está desactivada y reduce el ruido del log de sesión por redibujados repetidos.

## Añadido

- Ninguno.

## Mejoras

- Los logs de sesión deduplican las barras de progreso para reducir ruido.

## Corregido

- Se omiten consultas de credenciales en el escaneo de puertos cuando la autenticación está desactivada, evitando bloqueos del keyring.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualización

```bash
git pull origin main
```
