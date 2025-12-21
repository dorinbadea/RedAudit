# Roadmap de Mejora (4-6 semanas)

Este roadmap define mejoras concretas con criterios de salida medibles. No cambia
la vision del producto; enfoca calidad, arquitectura y ecosistema.

## Fase 1 (Semana 1): Quick wins

Objetivo: mejoras visibles, documentacion operativa y señales de calidad.

- Agregar badge de coverage en README y README_ES.
- Consolidar CONTRIBUTING en la raiz (apuntando a .github/).
- Revisar y actualizar issue templates (bug/feature).
- Corregir ResourceWarning si aparecen en tests.

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

- Subir cobertura real en redaudit/ > 90%.
- Agregar SECURITY_AUDIT.md con alcance y riesgos conocidos.
- Implementar rotacion de logs (RotatingFileHandler) con tests minimos.

Criterio de salida:

- Coverage verificada y publicada.
- Documento de seguridad revisado.
- Logs con rotacion activa y probada.

## Fase 4 (Semana 5): Ecosistema (opcional)

Objetivo: mejorar despliegue y extensibilidad.

- Dockerfile oficial + workflow para build/push.
- Evaluar sistema de plugins si hay casos reales.

Criterio de salida:

- Imagen reproducible y documentada.
- Decision de plugins documentada (implementado o postergado).
