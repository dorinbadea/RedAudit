# Release v4.5.17

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.17/docs/releases/RELEASE_NOTES_v4.5.17.md)

**Fecha:** 2026-01-11
**Version:** v4.5.17

## Resumen

Esta versión resuelve problemas críticos relacionados con la consistencia lógica del escaneo y el comportamiento del Deep Scan. Asegura que el barrido de puertos (`-p-` 65,535 puertos) se preserve siempre para Deep Scans completos, mientras optimiza inteligentemente los tiempos de escaneo para dispositivos de infraestructura bien identificados (routers/gateways) aprovechando señales de identidad existentes. También mejora la documentación sobre actualizaciones de instalación.

## Corregido

- **Lógica de Escaneo (BUG-01):** Solucionado un problema donde los puertos descubiertos por HyperScan a veces se sobrescribían si el escaneo posterior de Nmap devolvía cero puertos confirmados (debido a timeouts o filtrado agresivo). Ahora, los puertos de HyperScan siempre se preservan en el informe final.
- **Rendimiento Deep Scan (UX-03):** Solucionados tiempos de escaneo extremadamente lentos (25+ minutos) para FritzBox y otros routers.
  - **Cambio Lógico:** Dispositivos de infraestructura (routers, gateways) con **identidad fuerte** (score >= 3, fabricante conocido, versión detectada, <= 20 puertos) ahora alcanzan correctamente el umbral `identity_strong` y omiten la fase redundante de Deep Scan.
  - **Red de Seguridad:** Hosts marcados como "sospechosos" o con identidad débil **SIEMPRE** recibirán el barrido completo de 65,535 puertos (`-p-`), preservando la filosofía de seguridad estricta de RedAudit.
  - **Resultado:** Tiempos de escaneo de routers reducidos de 25+ min a ~2-3 min sin comprometer la cobertura de seguridad para hosts ambiguos.
- **Manejo de Entrada (BUG-02):** Solucionado un traceback de Python al presionar `Ctrl+C` durante el asistente interactivo. Ahora sale elegantemente.
- **CLI (BUG-03):** Añadido el flag faltante `--verbose` / `-v` al parser de argumentos.

## Documentación

- **Actualizaciones de Instalación (DOC-01/02):**
  - Actualizado `README.md` (y versión ES) para aclarar que RedAudit incluye un **mecanismo de actualización automática** vía el asistente (`sudo redaudit`).
  - Añadida nota para usuarios de **Ubuntu 24.04+ (Noble)** sobre errores `externally-managed-environment` (restricción pip), explicando que el instalador usa paquetes del sistema por defecto.

## Actualización

Para actualizar a esta versión, simplemente ejecuta el asistente:

```bash
sudo redaudit
# Selecciona "Sí"/"Yes" cuando pregunte por actualizaciones
```
