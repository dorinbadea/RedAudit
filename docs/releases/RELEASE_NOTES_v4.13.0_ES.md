[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.13.0/docs/releases/RELEASE_NOTES_v4.13.0.md)

# Notas de Versión v4.13.0 - Fase 4.13 Resiliencia

**Fecha de publicación**: 2026-01-17

## Resumen

Esta versión introduce la funcionalidad **Reintentos de Host Muerto** para mejorar la resiliencia del escaneo en redes con hosts que no responden. También incluye correcciones de i18n para las estimaciones de tiempo de los perfiles Nuclei.

## Añadido

- **Reintentos de Host Muerto** (`--dead-host-retries`): Nuevo flag CLI para abandonar hosts tras N timeouts consecutivos (predeterminado: 3). Evita atascos en hosts que no responden.
- **Integración ConfigurationContext**: Añadida propiedad `dead_host_retries` al wrapper de configuración tipada para acceso consistente.

## Corregido

- **i18n Estimaciones Nuclei**: Corregidas estimaciones de tiempo en el asistente:
  - `fast`: Mostraba ~15min, ahora muestra ~30-60min (realista)
  - `balanced`: Mostraba ~30min, ahora muestra ~1h (realista)
- **Truncamiento de Texto en Asistente**: Acortadas las descripciones de perfiles en español para evitar truncamiento en terminales estrechos.

## Actualización

```bash
sudo redaudit  # Opción 2: Comprobar actualizaciones
# o
pip install --upgrade redaudit
```

## Historial completo

Consulta [CHANGELOG_ES.md](https://github.com/dorinbadea/RedAudit/blob/main/ES/CHANGELOG_ES.md) para el historial completo.
