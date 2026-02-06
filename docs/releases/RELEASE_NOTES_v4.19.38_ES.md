[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.38/docs/releases/RELEASE_NOTES_v4.19.38.md)

# RedAudit v4.19.38 - Trazabilidad y Endurecimiento del Instalador

## Summary

Esta version refuerza la trazabilidad de operaciones de credenciales y endurece la generacion de configuracion del instalador, manteniendo las correcciones recientes de coherencia de reportes y estabilidad de riesgo SIEM.

## Added

- Eventos de auditoria de credenciales para operaciones de acceso/almacenamiento de proveedores (`credential_audit` en formato clave/valor sin secretos).

## Improved

- La documentacion de seguridad ahora aclara el comportamiento del backend de keyring en contextos headless/root y documenta los eventos de auditoria de credenciales.

## Fixed

- Coherencia de reportes parciales cuando Nuclei queda en estado parcial (nombre `PARTIAL_` y estado TXT alineados con el manifiesto).
- Estabilidad del riesgo SIEM por calculo de riesgo tras normalizacion/consolidacion de hallazgos y reasignacion de findings al host.
- La generacion del JSON de configuracion NVD en el instalador ahora usa `jq` si esta disponible y fallback a `python3`, evitando JSON crudo con `echo`.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Actualiza a `v4.19.38` desde el repositorio oficial.
2. Reejecuta el instalador si gestionas despliegues del sistema con `redaudit_install.sh`.
3. Valida tu pipeline con un escaneo completo y una reanudacion de Nuclei.
