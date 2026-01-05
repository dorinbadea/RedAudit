# RedAudit v4.0.3 Notas de Version

[![View in English](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v4.0.3.md)

**Fecha de lanzamiento**: 2026-01-05

## Highlights

- Enrutamiento de proxy aplicado de extremo a extremo via proxychains para herramientas externas
  (solo TCP connect).
- La CLI valida la presencia de proxychains e informa el uso de proxy durante el escaneo.
- Documentacion y tests alineados con el alcance real del proxy.

---

## Cambios

### Enrutamiento de Proxy

- Se agrego un wrapper de comandos en `CommandRunner` y se conecto con nmap, verificacion
  agentless, enriquecimiento HTTP/TLS, Nikto/WhatWeb/TestSSL y Nuclei.
- Limpieza de configuraciones temporales de proxychains al finalizar el escaneo.

### CLI

- `--proxy` ahora requiere proxychains y documenta el alcance solo TCP.

---

## Documentacion

- README, uso, manual y seguridad (EN/ES) actualizados con el requisito de proxychains
  y el alcance TCP-only.

---

## Tests

- Pruebas agregadas para wiring del wrapper de proxy y gating de proxychains en CLI.

---

## Instalacion

```bash
pip install --upgrade redaudit
# o
pip install git+https://github.com/dorinbadea/RedAudit.git@v4.0.3
```

---

## Enlaces

- [Changelog completo](../../ES/CHANGELOG_ES.md)
- [Documentacion](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
