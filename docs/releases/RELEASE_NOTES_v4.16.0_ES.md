# Notas de Version - v4.16.0

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.16.0/docs/releases/RELEASE_NOTES_v4.16.0.md)

## Resumen

RedAudit v4.16.0 introduce el **Modo Audit-Focus de Nuclei**, una optimizacion de rendimiento para redes con hosts multi-puerto. Esta version tambien incluye una correccion de renderizado de color de v4.15.1.

## Novedades

### Modo Audit-Focus de Nuclei

Cuando se detectan hosts con 3+ puertos HTTP, RedAudit ahora limita automaticamente el escaneo Nuclei a un maximo de **2 URLs por host**, priorizando puertos estandar (80, 443, 8080, 8443).

**Beneficios:**

- Reduce significativamente el tiempo de escaneo (~25min vs 1.5h para hosts complejos)
- Se enfoca en servicios principales donde es mas probable encontrar CVEs criticos
- Mantiene la efectividad de auditoria evitando problemas de timeout

**Visibilidad para el Usuario:**

```
[INFO] Nuclei: 25 -> 8 targets (audit focus)
```

### Correccion de Bug de Color (de v4.15.1)

- Los mensajes `[INFO]` ahora se renderizan correctamente (cyan) durante la visualizacion de barras de progreso
- Causa raiz: El markup Rich `[INFO]` se interpretaba como un tag desconocido
- Correccion: Usar objetos `Text()` de Rich para salida de color confiable

## Instrucciones de Actualizacion

```bash
pip install --upgrade redaudit
# o
git pull && pip install -e .
```

## Registro de Cambios Completo

Ver [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md) para detalles completos.
