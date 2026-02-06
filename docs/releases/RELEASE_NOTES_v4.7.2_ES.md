[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.7.2/docs/releases/RELEASE_NOTES_v4.7.2.md)

# RedAudit v4.7.2

**Fecha de lanzamiento:** 2026-01-15

## Resumen

Este hotfix corrige problemas criticos descubiertos durante el analisis del escaneo v4.7.1: timeouts en lotes de Nuclei y reintentos innecesarios de la API NVD.

## Corregido

### Timeout de Nuclei (Critico)

- **Problema**: Los lotes de Nuclei fallaban al 100% (5/5 lotes con timeout)
- **Causa raiz**: El timeout por defecto de `command_runner.py` era 60 segundos, demasiado corto para Nuclei
- **Fix**: Timeout aumentado a 600 segundos (10 minutos) para comandos Nuclei

### Manejo de 404 en API NVD

- **Problema**: Las respuestas 404 (CPE no encontrado) se reintentaban 3 veces innecesariamente
- **Causa raiz**: 404 no estaba en la lista de errores no reintentables
- **Fix**: Omitir reintentos inmediatamente en respuestas 404 (CPE no en NVD no es reintentable)

## Verificacion

- Pre-commit: Todos los hooks pasaron
- Tests: 40/40 tests especificos pasaron
- Analisis de session log confirmo timeout era 60s (ahora 600s)

## Actualizar

```bash
git pull
sudo redaudit --version  # Debe mostrar 4.7.2
```

## Archivos Relacionados

- [command_runner.py](../../redaudit/core/command_runner.py) - Fix timeout Nuclei
- [nvd.py](../../redaudit/core/nvd.py) - Fix skip 404
- [CHANGELOG.md](../../CHANGELOG.md) - Changelog completo
