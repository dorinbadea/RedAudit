# RedAudit v3.9.5 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/EN-English-blue)](./RELEASE_NOTES_v3.9.5.md)

**Fecha de Lanzamiento**: 2025-12-28

## Destacados

Esta versión introduce el **Pack de Firmas IoT** para detección de dispositivos smart home, más correcciones menores.

---

## Nuevas Funcionalidades

### Pack de Firmas IoT

Payloads UDP específicos por protocolo para detección automática de dispositivos smart home:

| Protocolo | Puerto(s) | Dispositivos |
|-----------|-----------|--------------|
| WiZ | 38899 | Bombillas inteligentes |
| Yeelight | 1982, 55443 | Bombillas inteligentes |
| Tuya/SmartLife | 6666, 6667 | Varios IoT |
| CoAP/Matter | 5683 | Dispositivos Matter |

Los dispositivos se etiquetan automáticamente con `asset_type: iot` en los informes.

### Fallback de Hostname por DNS Reverso

Los informes HTML ahora muestran hostnames de dispositivos IoT desde DNS reverso cuando el hostname estándar está vacío (ej: `wiz-9df9a6.fritz.box`).

---

## Correcciones

### Nombres de Producto NVD

- Se relajó la expresión regular de sanitización en búsqueda de CVEs para preservar puntos en nombres de productos
- `node.js` ya no se convierte incorrectamente en `nodejs`
- Corrige generación de CPE para múltiples frameworks

---

## Instalación

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
```

---

## Enlaces

- [Changelog Completo](../../ES/CHANGELOG_ES.md)
- [Documentación](../../docs/INDEX.md)
- [Lanzamientos en GitHub](https://github.com/dorinbadea/RedAudit/releases)
