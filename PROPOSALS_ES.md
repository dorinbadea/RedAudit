# Propuestas Arquitectónicas

Este documento recopila sugerencias arquitectónicas para versiones futuras, enfocándose en modularidad y testing.

## 1. Estrategia de Desacoplamiento de Código

**Estado**: COMPLETADO en v2.6
**Implementación**: RedAudit ahora es un paquete Python:

- `redaudit/core/`: Módulos principales (auditor, scanner, crypto, reporter, network)
- `redaudit/utils/`: Utilidades (constants, i18n)
- `redaudit.py` original preservado como wrapper de compatibilidad
**Beneficio**: Las herramientas estándar de Python (pip, pylint, pytest) ahora funcionan correctamente.

## 2. Suite de Verificación de Descifrado

**Estado Actual**: La lógica de descifrado se verifica manualmente.
**Propuesta**: Implementar tests de regresión automáticos `tests/test_crypto_roundtrip.py`:

1. Generar clave/salt efímera.
2. Cifrar payload.
3. Descifrar y asegurar igualdad.

## 3. Validación de Entorno de Ejecución

**Propuesta**: Añadir rutina `pre_flight_check()` que verifique:

- Versión Python >= 3.8.
- Presencia y versión de Nmap >= 7.0.
- Permisos de escritura en directorio de salida.

## 4. Integración CI/CD

**Estado**: COMPLETADO en v2.6
**Implementación**: `.github/workflows/tests.yml` proporciona:

- Testing automatizado en Python 3.9, 3.10, 3.11, 3.12
- Integración con Codecov para reportes de cobertura
- Linting con Flake8
