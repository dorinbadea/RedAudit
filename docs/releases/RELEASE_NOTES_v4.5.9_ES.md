# Notas de la Version v4.5.9

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.9/docs/releases/RELEASE_NOTES_v4.5.9.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta es una versión de **Mantenimiento/CI**.

Suprime alertas del linter (Bandit) sobre credenciales hardcodeadas en el script de laboratorio (`scripts/seed_keyring.py`), asegurando que el pipeline de GitHub Actions pase en verde.

## Corregido

- **CI/Lint**: Añadidas anotaciones `# nosec` en `seed_keyring.py` para manejar las credenciales de laboratorio esperadas.
