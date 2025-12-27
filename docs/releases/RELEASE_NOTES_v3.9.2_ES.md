# RedAudit v3.9.2 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.9.2.md)

**Fecha de lanzamiento**: 2025-12-27

## Highlights

Este hotfix asegura **la visualizacion correcta de version** tras auto-update.

---

## 🐛 Correcciones

### Deteccion de version en instalacion script

- Se aceptan sufijos con letra como `3.9.1a` en `redaudit/VERSION`, evitando el fallback `0.0.0-dev` tras auto-update.

---

## 📦 Instalacion

```bash
pip install --upgrade redaudit
# o
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.2
```

---

## 🔗 Enlaces

- [Changelog completo](../../CHANGELOG_ES.md)
- [Documentacion](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
