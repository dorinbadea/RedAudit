# Notas de versión v3.8.3 de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.3.md)

**Fecha de lanzamiento:** 2025-12-21  
**Enfoque:** UX de wizard y reportes

---

## Novedades

### Identidad del auditor en reportes

El wizard ahora solicita el nombre del auditor y lo incluye en reportes TXT/HTML.

### HTML bilingüe

Cuando el idioma de ejecución es español, RedAudit genera `report_es.html` junto al HTML principal.

---

## Correcciones

- **Duplicación de prompt** en opciones de escaneo de vulnerabilidades.
- **Colores de detalle** INFO/WARN/FAIL consistentes durante el progreso activo.
- **Progreso Net Discovery** ya no muestra 100% fijo antes de finalizar el último paso.

---

## Cambios

- **Footer HTML** neutral (licencia + GitHub) sin crédito personal del autor.

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

## Notas de actualización

Esta versión es compatible hacia atrás. No requiere cambios de configuración.

---

**Registro completo:** [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
