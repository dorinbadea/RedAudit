# Roadmap de Mejora (4-6 semanas)

Este roadmap define mejoras concretas con criterios de salida medibles. No cambia
la vision del producto; enfoca calidad, arquitectura y ecosistema.

## Fase 1 (Semana 1): Quick wins

Objetivo: mejoras visibles, documentacion operativa y señales de calidad.

- [x] Agregar badge de coverage en README y README_ES.
- [x] Consolidar CONTRIBUTING en la raiz (apuntando a .github/).
- [x] Revisar y actualizar issue templates (bug/feature).
- [ ] Corregir ResourceWarning si aparecen en tests (no se detectaron en la corrida actual).

Criterio de salida:

- README con badges actualizados y CONTRIBUTING visible en raiz.
- Templates activos y consistentes.
- Tests sin warnings nuevos.

## Fase 2 (Semanas 2-3): Arquitectura

Objetivo: reducir deuda y mejorar separacion de responsabilidades.

- Dividir auditor.py en modulos:
  - auditor.py (orquestacion)
  - auditor_scan.py (scans)
  - auditor_vuln.py (vulnerabilidades)
  - auditor_mixins.py (utilidades)
- Mantener API estable y tests intactos.

Criterio de salida:

- Ningun archivo > 2000 lineas.
- Tests existentes pasan sin cambios de comportamiento.

## Fase 3 (Semana 4): Calidad y seguridad

Objetivo: elevar confianza con metricas y documentacion clara.

- [/] Subir cobertura real en redaudit/ > 90% (actual: **76.05%**, objetivo: 85%+ en progreso).
  - [x] **Sesión 1 (23-dic):** 75.49% → 75.76% (+0.27%, 8 módulos)
    - crypto.py: 100% ✨, oui_lookup.py: 95.56%, +6 módulos a ~96%
  - [x] **Sesión 2 (23-dic):** 75.76% → 75.98% (+0.22%)
    - diff.py: 98.88% (casi perfecto)
  - [x] **Sesión 3 (24-dic AM):** 75.98% → 76.05% (+0.07%)
    - command_runner: 87.35%, +9 tests batch 2
  - [x] Total: **+0.56%**, 10 módulos mejorados, 30 tests nuevos, 659 tests pasando
  - [ ] **Próxima sesión:** Milestone 1 restante (entity_resolver, osquery, proxy, playbook, nuclei)
  - [ ] Luego: Milestone 2 (topology, siem, verify_vuln, etc.) → 82%
  - [ ] Final: Milestone 3 (reporter, scanner, wizard parcial) → 85%
  - [ ] Ver [walkthrough.md](file:///Users/dorin/.gemini/antigravity/brain/d7a69a12-cb77-4acc-9997-a9bf976aace9/walkthrough.md) para roadmap detallado
- [x] Agregar SECURITY_AUDIT.md con alcance y riesgos conocidos.
- [x] Implementar rotacion de logs (RotatingFileHandler) con tests minimos.
- [x] Probe HTTP/HTTPS breve en hosts silenciosos con vendor para enriquecer modelo/activo (fallback a metatítulos/H1/H2/alt si falta `<title>` y rutas de login comunes).
- [x] Ajustar heurística de `asset_type` para priorizar dispositivos (iphone/msi/etc.) sobre sufijos `fritz`.
- [x] Usar `http_title` como identidad auxiliar para nombrar activos y clasificar switches cuando no hay hostname.

Criterio de salida:

- Coverage verificada y publicada.
- Documento de seguridad revisado.
- Logs con rotacion activa y probada.

## Fase 4 (Semana 5): Ecosistema (opcional)

Objetivo: mejorar despliegue y extensibilidad.

- [x] Dockerfile oficial + workflow para build/push.
- [x] Corregir build de Docker (instalar dependencias de compilacion para `netifaces`).
- [x] Evaluar sistema de plugins (sin casos urgentes; se mantiene diferido en ROADMAP).

Criterio de salida:

- Imagen reproducible y documentada.
- Decision de plugins documentada (implementado o postergado).

## Validacion local (27-dic)

- `pre-commit run --all-files` (OK; black reformateo `redaudit/core/jsonl_exporter.py`).
- `pytest tests/ -v` (no disponible: `pytest` no instalado en este entorno).
- `python3 -m pytest tests/ -v` (no disponible: modulo `pytest` no instalado).
