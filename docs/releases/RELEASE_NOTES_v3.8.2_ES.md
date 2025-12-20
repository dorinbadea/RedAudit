# RedAudit v3.8.2 — Notas de la Versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.2.md)

**Fecha de lanzamiento:** 2025-12-20
**Enfoque:** Pulido UX

---

## Novedades

### Marca de Agua en Reportes HTML

Añadido footer profesional en reportes HTML con:

- Aviso de licencia GPLv3
- Crédito del autor (Dorin Badea)
- Enlace al repositorio GitHub

### Mejoras en Barras de Progreso

- **Spinner Eliminado**: Se eliminó `SpinnerColumn` de las barras de progreso (causaba congelaciones durante fases largas)
- El progreso ahora muestra: `descripción + barra + porcentaje + tiempo transcurrido`

---

## Resumen de Cambios

### Añadido

- Marca de agua profesional en reportes HTML

### Corregido

- Congelaciones en barras de progreso durante Net Discovery y Deep Scan

---

## Instalación

```bash
cd ~/RedAudit
git fetch origin
git checkout main
git pull
sudo ./redaudit_install.sh -y
```

---

## Notas de Actualización

Esta es una versión menor de pulido UX. No hay cambios disruptivos ni actualizaciones de configuración requeridas.

---

**Changelog completo:** [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
