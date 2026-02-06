# RedAudit v4.19.27 - Aviso Nuclei y cancelación de reanudación

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.27/docs/releases/RELEASE_NOTES_v4.19.27.md)

## Summary

Aclara el aviso de duración de Nuclei antes de iniciar el escaneo y garantiza que Ctrl+C cancele la reanudación de Nuclei sin stack trace.

## Added

- None.

## Improved

- None.

## Fixed

- El aviso de duración se centra en Nuclei y se muestra antes de iniciar el escaneo.
- Ctrl+C durante la reanudación de Nuclei cancela limpiamente sin stack trace.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios rompientes. Actualiza a v4.19.27.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.27/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.27/docs/INDEX.md)
