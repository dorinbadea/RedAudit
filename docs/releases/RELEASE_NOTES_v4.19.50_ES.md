# RedAudit v4.19.50 - UX de inicio y persistencia de idioma

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.50/docs/releases/RELEASE_NOTES_v4.19.50.md)

## Resumen

Esta version parche mejora la usabilidad en primer arranque y la visibilidad de actualizaciones en modo interactivo.

## Anadido

- No hay nuevas funcionalidades de usuario final en esta version.

## Mejorado

- Los avisos de actualizacion al inicio se muestran despues de renderizar banner/menu, para que el usuario los vea de inmediato.
- Los prompts del wizard son mas limpios al eliminar el prefijo decorativo `?`.

## Corregido

- El instalador ahora persiste el idioma seleccionado (`en`/`es`) en la configuracion de usuario (`~/.redaudit/config.json`).
- Una reinstalacion en ingles ya no vuelve a abrir en espanol por fallback exclusivo de locale.
- El instalador aplica permisos/propietario best-effort sobre la configuracion de idioma cuando se ejecuta como root.

## Pruebas

- Validacion interna completada.

## Actualizacion

- No se requiere ninguna accion.
