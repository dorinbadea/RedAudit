[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.39/docs/releases/RELEASE_NOTES_v4.19.39.md)

# RedAudit v4.19.39 - Endurecimiento de resiliencia de configuracion

## Summary

Este parche mejora la resiliencia en runtime al autocorregir archivos de configuracion locales malformados en lugar de degradar el comportamiento de forma silenciosa.

## Added

- Flujo automatico de autocorreccion para `~/.redaudit/config.json` cuando el payload es invalido.

## Improved

- Los archivos de configuracion invalidos ahora se conservan como `config.json.invalid.<timestamp>` antes de reconstruir valores por defecto.
- Los bloques `defaults` con tipo invalido ahora hacen fallback al esquema esperado.

## Fixed

- Comportamiento al inicio cuando el archivo de configuracion contiene JSON malformado o una raiz invalida.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Actualiza a `v4.19.39` desde el repositorio oficial.
2. Ejecuta un escaneo normal y confirma que tus valores persistidos siguen aplicandose correctamente.
3. Si tenias una configuracion malformada, revisa la copia `config.json.invalid.<timestamp>` generada.
