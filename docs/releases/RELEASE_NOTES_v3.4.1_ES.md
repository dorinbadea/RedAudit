# Notas de la versión v3.4.1 - Hotfix de Directorio de Salida

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.4.1.md)

**Fecha de publicación**: 2025-12-17

## Resumen

RedAudit v3.4.1 es un hotfix pequeño que corrige dónde se guardan los informes cuando se ejecuta con `sudo`.

## Correcciones

- **Directorio de salida por defecto bajo sudo**: Los informes ahora se guardan por defecto en la carpeta Documentos del usuario invocador (en lugar de `/root`).
- **Expansión de `~` bajo sudo**: Rutas como `--output ~/Documents/...` y defaults persistidos se expanden para el usuario invocador.
- **Propietario de archivos**: Se aplica `chown` best-effort al directorio de salida para evitar artefactos propiedad de root bajo el home del usuario.

## Instrucciones de actualización

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.1 - Hotfix pequeño, mejor experiencia.*
