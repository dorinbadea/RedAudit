[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.18/docs/releases/RELEASE_NOTES_v4.6.18.md)

# RedAudit v4.6.18 - Spray de Credenciales SSH

## Resumen

- Anade soporte de spray de credenciales para autenticacion SSH.
- Corrige errores de salida parcial de Nuclei y codificacion URL de NVD.

## Anadido

- **Spray de Credenciales SSH**: Prueba todas las credenciales de la lista spray en keyring hasta que una tenga exito. Permite una sola lista de credenciales para redes con multiples hosts que requieren diferentes autenticaciones.

## Mejorado

- Ninguno.

## Corregido

- **Salida Parcial de Nuclei**: Persistir hallazgos parciales cuando los lotes hacen timeout a maxima profundidad de division recursiva, en lugar de dejar el archivo de salida vacio.
- **Codificacion URL NVD**: Codificar parametros de busqueda que contengan espacios o caracteres especiales.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualizar

- `sudo redaudit` (auto-actualizacion)
- `sudo bash redaudit_install.sh -y`
