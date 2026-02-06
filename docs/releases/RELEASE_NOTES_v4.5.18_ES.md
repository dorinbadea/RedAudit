# Release v4.5.18

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.18/docs/releases/RELEASE_NOTES_v4.5.18.md)

**Fecha:** 2026-01-11
**Version:** v4.5.18

## Resumen

Este hotfix resuelve un problema crítico de despliegue en el script de configuración del Laboratorio (`scripts/setup_lab.sh`). Asegura que el objetivo Windows/Samba (IP `.30`) se despliegue correctamente usando la imagen moderna `elswork/samba` con volúmenes y configuración de usuario apropiados, resolviendo problemas con contenedores rotos o desactualizados de instalaciones previas.

## Corregido

- **Configuración de Lab (Hotfix)**:
  - Eliminación forzada del contenedor `target-windows` antes de la creación para asegurar un despliegue limpio.
  - Actualizado el comando de despliegue para la IP `172.20.0.30` para usar correctamente `elswork/samba` con volúmenes persistentes (`/srv/lab_smb/Public`) y credenciales de usuario predefinidas (`docker:password123`).
  - Asegura que el objetivo sea explotable/auditable según lo previsto en los Escenarios de Laboratorio RedAudit.

## Actualización

Para aplicar este arreglo a tu entorno de laboratorio:

1. Actualiza RedAudit:

   ```bash
   sudo redaudit
   # Selecciona "Sí" para actualizar
   ```

2. Vuelve a ejecutar el instalador del laboratorio (esto arreglará el contenedor):

   ```bash
   cd ~/RedAudit/scripts
   ./setup_lab.sh install
   ```
