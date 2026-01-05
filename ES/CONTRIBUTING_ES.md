# Guía de contribución

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](../CONTRIBUTING.md)

Esta es la guía canónica de contribución del repositorio. La versión en inglés está en `../CONTRIBUTING.md`.

Si estás leyendo esto desde la raíz del repositorio, usa:

- `CONTRIBUTING_ES.md` (Español)
- `../CONTRIBUTING.md` (English)

## Comprobaciones de Integración (Opcional)

Para validar el parseo con salida real de herramientas:

```bash
REDAUDIT_REAL_TOOLS=1 pytest tests/integration/test_real_tool_output.py -v
```

Notas:
- Requiere `nmap` instalado.
- El test levanta un servidor HTTP local y ejecuta `nmap` contra `127.0.0.1`.
