# Notas de la Version v4.15.0

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.15.0/docs/releases/RELEASE_NOTES_v4.15.0.md)

## Resumen

Sprint de rendimiento y UX centrado en paralelismo de HyperScan, optimizacion de escaneo Nuclei y consistencia de salida en terminal.

## Anadido

- **Barra de Progreso HyperScan**: Barra de progreso visual (magenta) mostrando completado de hosts durante la fase de descubrimiento HyperScan-First.
- **Perfil Auto-Fast Nuclei**: Deteccion automatica de hosts con 3+ puertos HTTP, cambiando a perfil "fast" (solo plantillas CVE) para prevenir timeouts en hosts complejos.

## Corregido

- **Paralelismo Real HyperScan**: Eliminado bloqueo de escaneo SYN que estaba serializando escaneos debido a problemas de contencion de scapy legacy. RustScan/asyncio ahora ejecutan en modo paralelo real.
- **Emojis Minimalistas en Terminal**: Reemplazados emojis coloridos por alternativas Unicode monocromaticas en 48 instancias en 10+ archivos:
  - Marca de verificacion: ``
  - Marca de error: ``
  - Advertencia: `⚠`
- **Correcciones de Tests**: Actualizado `test_session_log.py` para usar nuevos emojis minimalistas.

## Pruebas

- Anadidos `test_hyperscan_start_sequential_key_en` y `test_hyperscan_start_sequential_key_es` para verificar claves i18n.
- Todos los 1939 tests pasaron.
- Hooks de pre-commit pasaron.

## Actualizacion

```bash
git pull origin main
sudo bash redaudit_install.sh
```
