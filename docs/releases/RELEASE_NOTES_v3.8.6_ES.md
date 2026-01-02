# Notas de Versión v3.8.6 — Fix de Build Docker

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.6.md)

**Fecha de lanzamiento:** 2025-12-22

## Resumen

Este hotfix asegura que la imagen Docker se construya correctamente instalando las dependencias de compilación necesarias para `netifaces`. También mejora la captura de identidad en hosts silenciosos desde UI web y alinea las notas de versión recientes con el formato bilingüe de versiones anteriores.

---

## Corregido

### Build de Docker para netifaces

La imagen Docker ahora instala dependencias de compilación para que `pip install` pueda compilar `netifaces` durante el build.

### Titulos de identidad en hosts silenciosos

El probe HTTP ahora usa fallback a H1/H2 cuando falta `<title>`, mejorando la deteccion de modelo en pantallas de login.

---

## Documentación

- Se agregan badges EN/ES a las notas de versión de v3.8.4 y v3.8.5.

---

## Actualización

```bash
cd /ruta/a/RedAudit
git pull origin main
```

No se requieren cambios de configuración.

---

[Volver al README](../../ES/README_ES.md) | [Registro completo](../../ES/CHANGELOG_ES.md)
