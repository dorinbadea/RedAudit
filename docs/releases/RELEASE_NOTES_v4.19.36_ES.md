[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.36/docs/releases/RELEASE_NOTES_v4.19.36.md)

# RedAudit v4.19.36 - Lanzamiento de Impulso de Cobertura

Esta versión marca un hito significativo en la calidad de ingeniería de RedAudit. Hemos logrado un impulso integral en la cobertura de pruebas en todos los módulos core, asegurando una mayor confiabilidad y estabilidad de nivel empresarial.

## Resumen

El objetivo principal de esta versión fue eliminar la deuda técnica de pruebas y asegurar que cada ruta lógica crítica esté verificada. La cobertura global del proyecto ha alcanzado el **>98%**.

## Mejorado

- **Cobertura Core**: Incremento significativo en la cobertura de pruebas unitarias e integrales para todos los módulos principales.
- **Integración Nuclei**: Alcanzada una cobertura del **99.85%** en `redaudit/core/nuclei.py`, asegurando una orquestación robusta del escaneo de vulnerabilidades.
- **Lógica del Auditor**: Mejora de la cobertura en `redaudit/core/auditor.py` hasta el **97.92%**, cubriendo flujos complejos de reanudación de escaneos e informes.
- **Club del 100% de Cobertura**: Los siguientes módulos mantienen ahora una cobertura perfecta del **100%**:
  - `redaudit/core/webhook.py`
  - `redaudit/core/osquery.py`
  - `redaudit/core/nvd.py`
- **Pragmas Estratégicos**: Optimización del uso de `# pragma: no cover` para excluir con precisión solo bucles interactivos de UI y bloques defensivos de seguridad que no son testeables automáticamente.

## Pruebas

- **Tamaño de la Suite**: 2899 pruebas superadas.
- **Verificación**: Verificado usando `pytest --cov=redaudit --cov-report=term-missing`.
- **Lints**: Superadas todas las comprobaciones de `pre-commit`, incluyendo `black`, `flake8` y `bandit`.

## Actualización

```bash
pip install --upgrade redaudit
# O mediante código fuente
git pull origin main
sudo bash redaudit_install.sh
```
