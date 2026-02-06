# Notas de la Version v4.5.8

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.8/docs/releases/RELEASE_NOTES_v4.5.8.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta versión corrige un error `NoKeyringError` al ejecutar RedAudit o el Seeder de Credenciales como **root** en sistemas sin sesión de escritorio (Headless).

Introduce un fallback a `keyrings.alt.file.PlaintextKeyring` cuando el backend del sistema no está disponible.

## Soporte Root Headless

Al ejecutar como root (ej: `sudo redaudit`), si no hay un servicio de keyring seguro (GNOME Keyring, KWallet) conectado, RedAudit ahora almacenará automáticamente las credenciales en un archivo local protegido por permisos estrictos.

## Correcciones

- **Dependencia**: Añadido `keyrings.alt` a `redaudit_install.sh`.
- **Lógica Core**: Tanto `redaudit` como `scripts/seed_keyring.py` ahora manejan `NoKeyringError` correctamente.

## Instrucciones de Actualización

1. **Pull e Instalar**:

   ```bash
   git pull
   # Importante: Ejecuta instalador de nuevo para la dependencia keyrings.alt
   sudo bash redaudit_install.sh
   ```

2. **Re-sembrar Credenciales**:

   ```bash
   sudo python3 scripts/seed_keyring.py
   ```
