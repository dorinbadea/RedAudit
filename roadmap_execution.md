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

- [ ] Subir cobertura real en redaudit/ > 90% (actual: ~74.34%).
- [x] Agregar SECURITY_AUDIT.md con alcance y riesgos conocidos.
- [x] Implementar rotacion de logs (RotatingFileHandler) con tests minimos.
- [x] Probe HTTP/HTTPS breve en hosts silenciosos con vendor para enriquecer modelo/activo.
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
