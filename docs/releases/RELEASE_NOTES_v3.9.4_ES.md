# RedAudit v3.9.4 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.9.4.md)

**Fecha de lanzamiento**: 2025-12-28

## Highlights

Este hotfix mejora la **fiabilidad del parseo de descubrimiento de red**.

---

## Correcciones

### Pistas de dominio DHCP con prefijos

- Parseo de `Domain Name` y `Domain Search` aunque Nmap prefije lineas con `|` o indentacion.
- Recupera pistas de dominio internas que antes se omitian.

### Limpieza de nombres NetBIOS

- Recorta puntuacion final en nombres NetBIOS de salida nbstat.
- Mantiene limpio el inventario de activos (ej: `SERVER01` en lugar de `SERVER01,`).

---

## Instalacion

```bash
pip install --upgrade redaudit
# o
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.4
```

---

## Enlaces

- [Changelog completo](../../ES/CHANGELOG_ES.md)
- [Documentacion](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
