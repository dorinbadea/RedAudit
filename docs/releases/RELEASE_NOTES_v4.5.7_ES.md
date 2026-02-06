# Notas de la Version v4.5.7

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.7/docs/releases/RELEASE_NOTES_v4.5.7.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta es una **HOTFIX** relacionada con la Carga de Credenciales.

Corrige un problema donde ejecutar `seed_keyring.py` como usuario normal guardaba las credenciales en el keyring del usuario, haciendolas invisibles para `sudo redaudit` (que corre como root).

## Corregido

- **Visibilidad de Credenciales (Sudo)**
  - El updater ahora preserva el contexto root al ejecutar el auto-seed, asegurando que las credenciales esten disponibles para `sudo redaudit`.
  - `scripts/seed_keyring.py` ahora avisa si se ejecuta sin `sudo`.

## Instrucciones para Usuarios

Si ejecutaste el seeder previamente y RedAudit no ve las credenciales:

1. Actualiza a v4.5.7.
2. Ejecuta el seeder con `sudo`:

   ```bash
   sudo python3 scripts/seed_keyring.py
   ```

3. Ahora `sudo redaudit` las vera.
