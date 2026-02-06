# Notas de Lanzamiento v4.5.13

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.13/docs/releases/RELEASE_NOTES_v4.5.13.md)

**Fecha de Lanzamiento:** 2026-01-10

## Resumen

Este hotfix soluciona un cierre inesperado crítico en la fase de **Escaneo Autenticado**, causado por un manejo incorrecto de objetos `Host` (acceso legacy tipo diccionario). También refina la documentación de `LAB_SETUP` para aclarar las arquitecturas de despliegue óptimas (Nativo/VM vs Docker).

## Corregido

- **Error en Escaneo Autenticado (`AttributeError`)**:
  - **Problema**: El escáner intentaba acceder a propiedades del objeto `Host` (IP, etc.) usando sintaxis de diccionario (`host.get("ip")`), provocando un crash durante las auditorías SSH/Lynis.
  - **Solución**: Lógica actualizada para acceder correctamente a las propiedades mediante notación de punto (`host.ip`), manteniendo compatibilidad hacia atrás para tests.
  - **Impacto**: Los escaneos autenticados (SSH) ahora se completan sin errores.

## Documentación

- **Guía de Configuración del Laboratorio**:
  - Agregadas insignias de navegación por idioma.
  - Listado explícitamente **Windows** como host soportado para el Laboratorio Víctima.
  - Clarificado que **RedAudit (El Auditor)** funciona mejor en **Linux Nativo o VMs** para asegurar visibilidad de red L2, señalando las limitaciones de Docker en macOS/Windows.

## Actualización

```bash
git pull
sudo bash redaudit_install.sh  # (Opcional, principalmente actualización de código)
```
