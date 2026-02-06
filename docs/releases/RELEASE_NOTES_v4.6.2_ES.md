# RedAudit v4.6.2 - Optimización para Hosts Silenciosos

**Fecha:** 11-01-2026
**Tipo:** Release de Funcionalidad / Optimización

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.2/docs/releases/RELEASE_NOTES_v4.6.2.md)

Esta versión implementa una optimización crítica para infraestructura "Silenciosa" o "Muda" (ej. Repetidores, Hubs IoT) cuando la opción "Trust HyperScan" está activada.

### ⚡ Optimización para Hosts Silenciosos (Quiet Host)

Anteriormente, si **HyperScan** (Fase 0) encontraba **0 puertos abiertos** en un host, RedAudit v4.6.0 (modo paranoico) asumía que había fallado y recurría a un escaneo completo de 65.535 puertos (`-p-`). Esto causaba retrasos masivos (25+ minutos) en dispositivos legítimamente cerrados.

**Nuevo Comportamiento (`--trust-hyperscan` + 0 puertos):**

- RedAudit ahora "Confía en Resultados Negativos" de HyperScan.
- Si HyperScan descubre 0 puertos, RedAudit ejecuta una **Verificación de Cordura** (`Sanity Check`, `--top-ports 1000`) en lugar de `-p-`.
- **Resultado**: El tiempo de escaneo para estos dispositivos baja de ~25 minutos a <1 minuto, manteniendo un margen de seguridad razonable.

###  Correcciones

- **CI/Type Checking**: Resueltos 12 errores de tipado `mypy` en `auditor_scan.py` para asegurar pipelines de CI robustos.

---
**Changelog Completo**: <https://github.com/dorinbadea/RedAudit/compare/v4.6.1...v4.6.2>
