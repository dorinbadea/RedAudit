# RedAudit v4.18.0 - Correcciones UX y Documentación

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.0/docs/releases/RELEASE_NOTES_v4.18.0.md)

## Resumen

Esta versión corrige bugs visuales durante la visualización de barras de progreso y mejora la documentación para las opciones de configuración de Nuclei.

## Corregido

- **Bugs de Color con Rich Progress**: Corregidos mensajes [WARN], [OK] e [INFO] que aparecían blancos durante barras de progreso.
  - Causa raíz: La creación de un nuevo Console() evitaba el Rich progress activo, perdiendo el formato de color.
  - Corrección: Añadido seguimiento `_active_progress_console` en UIManager para asegurar el uso correcto de la consola.
  - También corregidos mensajes heartbeat de Deep Scan y Net Discovery para usar objetos `Text()` para salida de color fiable.

## Mejorado

- **Prompts del Wizard Acortados**: Reducida la truncación en terminal acortando prompts:
  - `nuclei_full_coverage_q`: Acortado para prevenir wrap de terminal en ventanas estrechas.
  - `trust_hyperscan_q`: Simplificado para claridad manteniendo la intención.

## Documentación

- **Sección Configuración Nuclei**: Añadida documentación completa a las guías USAGE (EN/ES):
  - Perfiles de escaneo (fast/balanced/full) con estimaciones de tiempo.
  - Opción de cobertura completa explicada como solo-wizard (no es un flag CLI).
  - RustScan documentado como mejora de rendimiento opcional para HyperScan.
- **Actualizaciones Referencia CLI**: Añadidos flags faltantes `--profile` y `--nuclei-timeout` a la referencia CLI del MANUAL.
- **Corrección Crítica**: Clarificado que `--nuclei-full` NO existe como flag CLI; la cobertura completa es una opción interactiva solo en el wizard.

## Testing

- Los 1945 tests pasan.
- Pre-commit hooks pasan.
- Verificación manual de salida de color Rich durante barras de progreso.

## Actualizar

```bash
cd /ruta/a/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.0/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.18.0/docs/INDEX.md)
