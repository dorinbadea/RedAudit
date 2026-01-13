[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.9/docs/releases/RELEASE_NOTES_v4.6.9.md)

# RedAudit v4.6.9 - Gating por Identidad y Informe Parcial de Nuclei

## Summary

Esta version reduce tiempos en dispositivos de infraestructura sin perder evidencia usando senales de identidad (titulo/servidor HTTP y tipo de dispositivo) para controlar deep scans y herramientas web pesadas. Tambien reporta ejecuciones parciales de Nuclei cuando hay timeouts por lote.

## Added

- Helper compartido de identidad de infraestructura usado en gating web y falsos positivos de Nuclei.
- Campos de resumen de Nuclei para ejecuciones parciales: `partial`, `timeout_batches`, `failed_batches`.
- Sonda HTTP rapida en hosts silenciosos para resolver identidad antes.

## Improved

- La decision de deep scan considera evidencia HTTP (titulo/servidor) y tipo de dispositivo para evitar escalados innecesarios.
- El escaneo de apps web (sqlmap/ZAP) se omite en UIs de infraestructura cuando la identidad indica router/switch/AP.
- Documentacion actualizada en README, manuales, uso, troubleshooting, security y esquema de informe.

## Fixed

- Los timeouts de Nuclei ahora se reportan como ejecuciones parciales en lugar de quedar ocultos.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `git pull origin main`
- `sudo bash redaudit_install.sh`
- Reabrir la terminal para refrescar la version instalada
