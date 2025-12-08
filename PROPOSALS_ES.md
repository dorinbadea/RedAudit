# Propuestas Arquitectónicas

Este documento recopila sugerencias arquitectónicas para versiones futuras, enfocándose en modularidad y testing.

## 1. Estrategia de Desacoplamiento de Código
**Estado Actual**: `redaudit_install.sh` actúa como un archivo auto-extraíble.
**Propuesta**: Separar la distribución en:
- `bin/redaudit`: Script de punto de entrada.
- `lib/redaudit/`: Estructura de paquete Python estándar.
**Beneficio**: Permite el uso de herramientas estándar (pip, pylint) sin pasos de extracción.

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

```yaml
name: Verify RedAudit
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: sudo apt-get update && sudo apt-get install -y nmap python3-nmap python3-cryptography
      - name: Run Verification Script
        run: bash redaudit_verify.sh
        continue-on-error: true # Expect failure on binary path but check syntax
      - name: Syntax Check
        run: |
          bash -n redaudit_install.sh
          python3 -m py_compile redaudit_decrypt.py
      - name: Run Sanitization Tests
        run: python3 tests/test_sanitization.py
```
