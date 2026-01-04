# Roadmap de Mejora (4-6 semanas)

Este roadmap define mejoras concretas con criterios de salida medibles. No cambia
la visión del producto; se centra en calidad, arquitectura y ecosistema.

## Fase 1 (Semana 1): Quick wins

Objetivo: mejoras visibles, documentación operativa y señales de calidad.

- [x] Añadir badge de cobertura en README y README_ES.
- [x] Consolidar CONTRIBUTING en la raíz (sustituyendo .github/CONTRIBUTING.md).
- [x] Revisar y actualizar issue templates (bug/feature).
- [ ] Corregir ResourceWarning si aparecen en tests (no se detectaron en la ejecución actual).
- [ ] Corregir warnings de asyncio en tests de hyperscan (coroutines no awaited).

Criterio de salida:

- README con badges actualizados y CONTRIBUTING visible en raíz.
- Templates activos y consistentes.
- Tests sin warnings nuevos.

## Fase 2 (Semanas 2-3): Arquitectura

Objetivo: reducir deuda y mejorar separación de responsabilidades.

- Dividir auditor.py en módulos:
  - auditor.py (orquestación)
  - auditor_scan.py (scans)
  - auditor_vuln.py (vulnerabilidades)
  - auditor_components.py (utilidades)
- Mantener API estable y tests intactos.

Criterio de salida:

- Ningún archivo > 2000 líneas.
- Tests existentes pasan sin cambios de comportamiento.

## Fase 3 (Semana 4): Calidad y seguridad

Objetivo: elevar confianza con métricas y documentación clara.

- [/] Subir la cobertura real en `redaudit/` > 90% (actual: **76.05%**, objetivo: 85%+ en progreso).
  - [x] **Sesión 1 (23-dic):** 75.49% → 75.76% (+0.27%, 8 módulos)
    - crypto.py: 100% ✨, oui_lookup.py: 95.56%, +6 módulos a ~96%
  - [x] **Sesión 2 (23-dic):** 75.76% → 75.98% (+0.22%)
    - diff.py: 98.88% (casi perfecto)
  - [x] **Sesión 3 (24-dic AM):** 75.98% → 76.05% (+0.07%)
    - command_runner: 87.35%, +9 tests batch 2
  - [x] **Sesión 4 (25-30 dic):** Gran impulso de cobertura
    - updater.py: ~93%
    - traffic.py: ~94%
    - hyperscan.py: ~90%
    - topology.py: ~91%
    - Overall: ~93.03%
  - [x] Total: **+17%**, 2200+ tests pasando (según ejecución local de la época).
  - [ ] **Próxima sesión:** Milestone 1 restante (entity_resolver, osquery, proxy, playbook, nuclei)
  - [ ] Luego: Milestone 2 (topology, siem, verify_vuln, etc.) → 82%
  - [ ] Final: Milestone 3 (reporter, scanner, wizard parcial) → 85%
  - [ ] Ver notas locales (no versionadas) para el roadmap detallado
- [x] Agregar SECURITY_AUDIT.md con alcance y riesgos conocidos.
- [x] Implementar rotación de logs (RotatingFileHandler) con tests mínimos.
- [x] Probe HTTP/HTTPS breve en hosts silenciosos con vendor para enriquecer modelo/activo (fallback a metatítulos/H1/H2/alt si falta `<title>` y rutas de login comunes).
- [x] Ajustar heurística de `asset_type` para priorizar dispositivos (iphone/msi/etc.) sobre sufijos `fritz`.
- [x] Usar `http_title` como identidad auxiliar para nombrar activos y clasificar switches cuando no hay hostname.

Criterio de salida:

- Cobertura verificada y publicada.
- Documento de seguridad revisado.
- Logs con rotacion activa y probada.

## Fase 4 (Semana 5): Ecosistema (opcional)

Objetivo: mejorar despliegue y extensibilidad.

- [x] Dockerfile oficial + workflow para build/push.
- [x] Corregir build de Docker (instalar dependencias de compilación para `netifaces`).
- [x] Evaluar sistema de plugins (sin casos urgentes; se mantiene diferido en ROADMAP).

Criterio de salida:

- Imagen reproducible y documentada.
- Decisión de plugins documentada (implementado o postergado).

## Validación local (27-dic)

- `pre-commit run --all-files` (OK).
- `.venv/bin/python -m pytest tests/ -v` (OK: 2209 tests passed según ejecución local).
