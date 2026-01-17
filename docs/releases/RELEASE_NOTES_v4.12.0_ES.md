[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.12.0/docs/releases/RELEASE_NOTES_v4.12.0.md) [![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.12.0/docs/releases/RELEASE_NOTES_v4.12.0_ES.md)

# Notas de Versión RedAudit v4.12.0

## Resumen

RedAudit v4.12.0 es una **versión de optimización de rendimiento** que introduce **gating de herramientas basado en perfil** para Nikto. Esta versión reduce significativamente el tiempo de escaneo en redes con muchos dispositivos de infraestructura (routers, switches, puntos de acceso) al omitir inteligentemente los escaneos de Nikto según el perfil Nuclei seleccionado.

## Añadido

- **Gating de Nikto por Perfil**: El perfil Nuclei (`--profile`) ahora controla la ejecución de Nikto:
  - `fast`: Omite Nikto completamente para máxima velocidad.
  - `balanced`: Omite Nikto en dispositivos de infraestructura detectados (routers, switches, APs).
  - `full`: Ejecuta Nikto en todos los hosts web (comportamiento original).
- **Detección de Infraestructura Mejorada**: Mejorado `is_infra_identity()` para detectar más patrones de dispositivos de red (Fritz!Box, MikroTik, Ubiquiti, Synology, QNAP, y otros).

## Mejorado

- **Rendimiento de Escaneo**: Las redes con muchos dispositivos de infraestructura (como routers domésticos, dispositivos NAS y puntos de acceso) verán tiempos de escaneo significativamente reducidos al usar el perfil `balanced`.
- **Arquitectura de Código**: La lógica de gating de Nikto se movió a un método dedicado `_should_run_nikto()` para mejor separación de responsabilidades.

## Corregido

- **Changelog en Español**: Añadida entrada v4.12.0 faltante en `ES/CHANGELOG_ES.md`.

## Pruebas

- **Automatizadas**: Suite completa de `pytest` pasada (1816 tests).
- **Comportamiento Esperado**:
  - Perfil `balanced`: Fritz!Box y routers similares deberían mostrar `nikto_skipped: infra_keyword:fritz` en los logs.
  - Perfil `fast`: Nikto omitido completamente con `nikto_skipped: profile_fast`.
  - Perfil `full`: Nikto se ejecuta en todos los hosts web como antes.

## Actualización

Sin cambios disruptivos. Actualizar e instalar dependencias:

```bash
git pull origin main
pip install -e .
```
