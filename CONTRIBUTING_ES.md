# Guía de Contribución

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](CONTRIBUTING.md)

## Visión General

RedAudit se adhiere a estándares estrictos de codificación y commits para mantener auditabilidad y confiabilidad.

## Estándares de Código

### Python

- **Formato**: Cumple con PEP 8
- **Type Hinting**: Las firmas de funciones deben incluir hints de tipos
- **Seguridad**: No usar `shell=True` en llamadas subprocess. Toda entrada de usuario debe ser sanitizada
- **Concurrencia**: Las operaciones de I/O de red deben ser thread-safe

### Estructura del Paquete

El código está organizado como un paquete Python:

- `redaudit/core/`: Funcionalidad principal (auditor, scanner, crypto, reporter, network, nvd, diff, proxy)
- `redaudit/utils/`: Utilidades (constants, i18n, config)
- `tests/`: Suites de tests

### Testing

- **Validación Local**: Ejecuta `python3 -m pytest tests/` antes de enviar PRs
- **Script de Verificación**: Ejecuta `bash redaudit_verify.sh` para chequeos de entorno
- **CI/CD**: GitHub Actions ejecuta tests automáticamente en PRs

## Proceso de Pull Request

1. **Branching**: Crea ramas de feature desde `main`
   - Nomenclatura: `feature/descripcion-corta` o `fix/issue-id`
2. **Commits**: Usa mensajes de commit semánticos
   - `feat: add ssl inspection`
   - `fix: logic error in thread pool`
3. **Documentación**: Actualiza `README.md` y archivos en `docs/` para cambios arquitectónicos
4. **Tests**: Incluye cobertura de tests para nueva funcionalidad

## Reportar Issues

- **Bug Reports**: Proporciona pasos para reproducir, versión de SO, y logs sanitizados
- **Seguridad**: Reporta vulnerabilidades vía canal privado con etiqueta `security`

## Estilo de Código

- Mantén el código limpio y comentado
- Sigue PEP 8 para Python
- Scripts de shell: Cumplir POSIX o claramente específicos de Bash

## Licencia

Al contribuir a RedAudit, aceptas que tus contribuciones serán licenciadas bajo la **GNU General Public License v3.0 (GPLv3)**.
