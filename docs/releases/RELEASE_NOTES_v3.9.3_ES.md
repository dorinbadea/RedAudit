# RedAudit v3.9.3 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.9.3.md)

**Fecha de lanzamiento**: 2025-12-27

## Highlights

Este hotfix mejora la **fidelidad de informes** y los **titulos de hallazgos**.

---

## Correcciones

### Consolidacion de hallazgos con TestSSL

- Preserva `testssl_analysis` y observaciones relacionadas cuando se combinan hallazgos.
- Evita perder alertas TLS en salidas HTML/JSON.

### Titulos HTML para hallazgos sin descripcion

- Si un hallazgo no tiene `descriptive_title`, el HTML genera un titulo util (ej: `Web Service Finding on Port 443`) en vez de la URL.

---

## Instalacion

```bash
pip install --upgrade redaudit
# o
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.3
```

---

## Enlaces

- [Changelog completo](../../ES/CHANGELOG_ES.md)
- [Documentacion](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
