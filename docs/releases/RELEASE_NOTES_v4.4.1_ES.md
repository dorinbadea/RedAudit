# RedAudit v4.4.1 - Paridad CI y compatibilidad con Python 3.9

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.4.1/docs/releases/RELEASE_NOTES_v4.4.1.md)

Esta versión se centra en la paridad con CI y la compatibilidad de dependencias en Python 3.9 para evitar fallos solo en CI.

## Corregido

- El lock de desarrollo en Python 3.9 ahora selecciona versiones compatibles de iniconfig, pytest-asyncio, markdown-it-py, pycodestyle y pyflakes para evitar conflictos de resolución.
- El lock de runtime ahora selecciona una versión de markdown-it-py compatible con Python 3.9 al ejecutarse en 3.9.

## Añadido

- Script de paridad local `scripts/ci_local.sh` para ejecutar pre-commit y pytest en Python 3.9-3.12.

## Cambiado

- Los tests de flujos completos de escaneo desactivan HyperScan-first para mantener el tiempo de ejecución acotado sin afectar la cobertura lógica.

## Actualizacion

```bash
cd RedAudit
git pull origin main
pip install -r requirements.txt
```
