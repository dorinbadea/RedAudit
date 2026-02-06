# Notas de la Version v4.5.12

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.12/docs/releases/RELEASE_NOTES_v4.5.12.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta actualización resuelve el error "Externally Managed Environment" (PEP 668) encontrado al instalar dependencias de Python en distribuciones modernas como Ubuntu 24.04 (Noble) y versiones recientes de Kali Linux.

## Corregido

- **Lógica de Reintento Inteligente de Pip**:
  - El instalador ahora maneja robustamente los fallos de `pip install`. Si la instalación estándar falla debido a restricciones de entorno gestionado (PEP 668), reintenta automáticamente con el flag `--break-system-packages`.
  - Esto asegura que dependencias críticas como `pysnmp` (que pueden faltar en los repositorios APT) puedan instalarse en todo el sistema para que RedAudit funcione correctamente.

## Verificación

Si anteriormente viste `error: externally-managed-environment` o `[WARN] pip install failed`, simplemente ejecuta:

```bash
git pull
sudo bash redaudit_install.sh
```

El script ahora evitará inteligentemente la restricción para asegurar una instalación completa.
