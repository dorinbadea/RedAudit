[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.29/docs/releases/RELEASE_NOTES_v4.19.29.md)

# RedAudit v4.19.29 - Persistencia de playbooks de remediacion

## Summary
- Los playbooks de remediacion se guardan en el JSON y se reconstruyen para HTML si faltan.

## Added
- Ninguno.

## Improved
- La regeneracion HTML reconstruye playbooks de remediacion cuando no estan presentes en el JSON.

## Fixed
- La seccion de Playbook Remediation se muestra de forma consistente en HTML regenerados.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No requiere accion.
