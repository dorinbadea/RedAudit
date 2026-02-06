# Notas de la Version v4.5.11

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.11/docs/releases/RELEASE_NOTES_v4.5.11.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta actualización corrige un fallo de instalación en distribuciones modernas de Linux (ej: Ubuntu 24.04 Noble) donde `python3-pysnmp` ya no está disponible en los repositorios.

El instalador ahora trata `python3-pysnmp` como un paquete del sistema opcional e intenta un fallback o advertencia elegante, asegurando que la instalación principal de RedAudit se complete con éxito incluso si esta librería específica no se puede instalar vía APT.

## Corregido

- **Instalador Universal**:
  - `python3-pysnmp` ahora se instala en un paso separado y opcional que no detiene el script si falla.
  - Corregido un error de duplicación de código en `redaudit_install.sh` introducido en v4.5.10.

## Instrucciones de Actualización

```bash
git pull
sudo bash redaudit_install.sh
```
