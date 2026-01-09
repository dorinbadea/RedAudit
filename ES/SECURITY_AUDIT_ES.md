# Auditoría de Seguridad (2026-01-09)

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](../SECURITY_AUDIT.md)

## Alcance

- Revisión del código fuente y comprobaciones automatizadas del proyecto RedAudit.
- Enfoque en manejo de datos, uso de privilegios, ejecución de subprocesos y seguridad de salidas.
- Esto no es un pentest ni una auditoría externa.

## Metodología

- Revisión estática de módulos core y flujo de orquestación.
- Comprobaciones automatizadas locales: `pre-commit run --all-files`.
- Ejecución de tests: `.venv/bin/python -m pytest tests/ -v --cov=redaudit --cov-report=term-missing`.

## Resumen

- Estado: revisión interna best-effort (v4.4.4).
- No se han identificado vulnerabilidades críticas conocidas en esta revisión.
- La cobertura es alta (~90%); alta confianza en la lógica core y la mayoría de casos límite.

## Controles Observados

- Validación de entrada y helpers de sanitización para IPs/hostnames.
- Defaults defensivos (soporte dry-run, fallbacks best-effort).
- Rotación de logs para reducir crecimiento sin límite.
- Soporte de cifrado para informes cuando cryptography está disponible.
- CI usa pre-commit, lint y tests en Python 3.9-3.12.
- Smart-Throttle (AIMD) previene DoS de red durante el escaneo.
- Targeting basado en generadores previene agotamiento de memoria en redes grandes.

## Limitaciones

- La cobertura está cerca del objetivo; el área interactiva (wizard) sigue menos testeada.
- No se ha realizado pentest externo ni modelado de amenazas.
- El comportamiento de herramientas externas (nmap, nikto, nuclei, etc.) se asume correcto y no se audita aquí.

## Recomendaciones (Priorizadas)

1) Aumentar cobertura en `redaudit/core/*` con tests unitarios específicos para paths de error.
2) Añadir tests explícitos para comportamiento de rotación de logs y manejo de errores.
3) Documentar un modelo de amenazas formal y revisitar riesgos trimestralmente.
4) Considerar revisión periódica de dependencias para herramientas externas y paquetes Python.

## Evidencia

- pre-commit: passed.
- pytest: 1465 passed, 1 skipped.
- Cobertura: ~90%.
