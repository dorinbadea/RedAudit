# RedAudit v4.19.51 - Alineacion de politica de config del instalador

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.51/docs/releases/RELEASE_NOTES_v4.19.51.md)

## Resumen

Este parche alinea el comportamiento del instalador con la experiencia esperada: reinstalacion manual limpia y auto-update conservando preferencias.

## Anadido

- No hay nuevas funcionalidades de usuario final en esta version.

## Mejorado

- La reinstalacion manual ahora aplica el idioma elegido en el instalador desde una config limpia.
- El flujo de auto-update conserva preferencias existentes del usuario (idioma, API key y defaults).

## Corregido

- Reinstalar en ingles ya no abre en espanol por configuracion persistida antigua.
- Guardar la API key de NVD durante instalacion ahora hace merge seguro y ya no sobrescribe `defaults.lang`.

## Pruebas

- Validacion interna completada.

## Actualizacion

- No se requiere ninguna accion.
