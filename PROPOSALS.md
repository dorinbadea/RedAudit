# Propuestas de Mejora (Non-Binding)

Este documento recoge sugerencias arquitectónicas para futuras versiones, sin alterar el núcleo actual (v2.3.1).

## 1. Desacoplar el código Python
**Estado Actual**: `redaudit_install.sh` contiene todo el código Python en un bloque `cat << 'EOF'`.
**Propuesta**: Separar en dos archivos:
- `install.sh`: Solo lógica de instalación (apt, alias, copy).
- `src/redaudit.py`: El código fuente limpio.
**Beneficio**: Facilita el linting, testeo y revisión de código sin regenerar el instalador.

## 2. Tests para el Descifrador
**Estado Actual**: `redaudit_decrypt.py` se prueba manualmente.
**Propuesta**: Añadir `tests/test_decrypt.py` que:
1. Genere una clave y salt dummy.
2. Cifre un string.
3. Invoque `redaudit_decrypt.py` (o sus funciones importadas) para verificar el round-trip.

## 3. Validación de Versión Python
**Estado Actual**: Se asume `python3` (normalmente 3.10+ en Kali).
**Propuesta**: Añadir check explícito de versión (>= 3.8) en el instalador para evitar errores de sintaxis en distros antiguas.
