# Notas de Versión v3.10.1

**Fecha de Publicación:** 2026-01-02
**Nombre clave:** Consistencia de Identidad y Hints de Vendor

## Resumen

Esta versión de parche aborda recomendaciones de auditoría para la consistencia del enriquecimiento de identidad. Asegura que las direcciones MAC descubiertas vía neighbor cache pasivo disparen lookups OUI online, consolida los hostnames DNS reverse en el registro canónico, e introduce inferencia de vendor basada en hostname como fallback cuando el lookup OUI falla (ej: para MACs randomizadas).

## Nuevas Funcionalidades

### Módulo Vendor Hints

Nueva utilidad (`redaudit/utils/vendor_hints.py`) que infiere el fabricante del dispositivo desde patrones de hostname cuando el lookup OUI no está disponible:

- Reconoce patrones como `iPhone`, `Galaxy`, `Pixel`, `MacBook`, `iPad`, `FRITZ`, `Xbox`, etc.
- Devuelve vendor con sufijo `(guess)` para indicar el método de inferencia
- Prioridad: lookup OUI > coincidencia de patrones de hostname

## Correcciones

### Enriquecimiento MAC desde Neighbor Cache

Las direcciones MAC descubiertas vía `ip neigh` (neighbor cache pasivo) ahora disparan un lookup OUI online vía `macvendors.com`, asegurando identificación consistente del vendor en todos los métodos de descubrimiento.

### Consolidación DNS Reverse

Los lookups DNS reverse de Fase 0 (bajo impacto) almacenados en `phase0_enrichment.dns_reverse` ahora se consolidan en el campo canónico `host.dns.reverse` si está vacío. Esto asegura:

- Visualización consistente del hostname en reportes HTML y TXT
- Resolución de entidades correcta usando todas las fuentes de hostname disponibles
- Mejor puntuación de identidad para decisiones de SmartScan

### Consistencia del Flujo de Datos

Corregidas brechas donde los datos de enriquecimiento de bajo impacto no se propagaban a consumidores posteriores:

- `entity_resolver.py`: Ahora usa `phase0_enrichment.dns_reverse` como fallback
- `reporter.py`: El reporte TXT usa el nuevo helper `_get_hostname_fallback()`
- `html_reporter.py`: Usa `get_best_vendor()` para visualización de vendor con fallback de hostname

## Pruebas

- Añadido `tests/test_audit_fixes.py` con tests de integración para consolidación DNS
- Añadido `tests/test_mac_enrichment.py` para vendor hints y enriquecimiento de neighbor cache
- Más de 2354 tests pasando

## Notas de Actualización

Esta es una versión de parche compatible hacia atrás. No se requieren cambios de configuración.

---

[Changelog completo](../../ES/CHANGELOG_ES.md) | [Índice de Documentación](../INDEX.md)
