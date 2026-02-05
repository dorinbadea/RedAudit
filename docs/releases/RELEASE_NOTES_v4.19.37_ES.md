[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.37/docs/releases/RELEASE_NOTES_v4.19.37.md)

# RedAudit v4.19.37 - Consistencia de Nuclei y Endurecimiento de Runtime

## Resumen

Esta versión refuerza la coherencia del reporting de Nuclei y mejora la robustez del tratamiento de metadatos runtime en la expansión de alcance.

## Añadido

- Ninguno.

## Mejorado

- La terminología del informe HTML en español para metadatos de expansión de alcance queda completamente localizada.
- El mensaje de cobertura completa ahora indica de forma explícita que se omiten los guardarraíles de auto-switch para respetar el perfil seleccionado.

## Corregido

- La contabilidad de objetivos de Nuclei se mantiene coherente cuando leak-follow añade objetivos extra.
- Los contadores runtime de expansión de alcance ahora se parsean de forma segura cuando hay campos numéricos persistidos malformados.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualización

```bash
pip install --upgrade redaudit
# O mediante código fuente
git pull origin main
sudo bash redaudit_install.sh
```
