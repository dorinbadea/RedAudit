# Notas de la versión v3.4.2 - Hotfix del Directorio de Salida en Wizard

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.4.2.md)

**Fecha de publicación**: 2025-12-17

## Resumen

RedAudit v3.4.2 es un hotfix pequeño que mejora la experiencia del wizard interactivo cuando se ejecuta con `sudo`.

## Correcciones

- **Prompt del directorio de salida (sudo)**: Si un default persistido antiguo apunta a `/root/...`, RedAudit lo reescribe automáticamente a la carpeta `Documentos` del usuario invocador.

## Instrucciones de actualización

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.2 - Hotfix pequeño, defaults más limpios.*
