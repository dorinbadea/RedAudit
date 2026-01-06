# Notas de la Versión RedAudit v4.1.0

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.1.0/docs/releases/RELEASE_NOTES_v4.1.0.md)

**Fecha de Lanzamiento:** 2026-01-06

---

## Optimizaciones de Rendimiento

### Pre-escaneo HyperScan-First Secuencial

La arquitectura v4.1 introduce una fase de pre-escaneo secuencial que se ejecuta **antes** del fingerprinting paralelo con nmap:

1. **Problema Resuelto:** Agotamiento de descriptores de archivo al ejecutar escaneos de 65,535 puertos concurrentemente en múltiples hosts
2. **Solución:** Ejecutar HyperScan-First secuencialmente con `batch_size=2000` (subido de 100 en modo concurrente)
3. **Resultado:** Escaneo general más rápido sin errores de descriptores de archivo

```
┌─────────────────┐   ┌──────────────────┐   ┌─────────────────┐
│ Net Discovery   │──▶│ HyperScan-First  │──▶│ nmap Paralelo   │
│ (ARP, mDNS)     │   │ (Secuencial)     │   │ Fingerprinting  │
└─────────────────┘   └──────────────────┘   └─────────────────┘
```

### Reuso de Puertos Masscan

Cuando masscan ya ha descubierto puertos (p. ej., via flag `--masscan`), HyperScan-First reutiliza esos resultados en lugar de re-escanear.

---

## Nuevas Características

### Lookup Online de Fabricante OUI

Cuando las herramientas locales (arp-scan, netdiscover) devuelven "Unknown" como fabricante, RedAudit ahora recurre a la **API de macvendors.com** para enriquecimiento de fabricante MAC.

Antes de v4.1:

```json
{"mac": "d4:24:dd:07:7c:c5", "vendor": "(Unknown)"}
```

Después de v4.1:

```json
{"mac": "d4:24:dd:07:7c:c5", "vendor": "AVM GmbH"}
```

### Integración Básica de sqlmap

RedAudit ahora integra **sqlmap** para detección automática de inyección SQL en objetivos web:

- Ejecuta en modo batch (no interactivo)
- Rastrea formularios y parámetros automáticamente
- Usa escaneo inteligente para detección rápida
- Detecta automáticamente la instalación de sqlmap

**Instalación:** sqlmap ahora está incluido en `redaudit_install.sh`.

---

## Mejoras

### Optimización de Comandos Nmap

Eliminadas flags redundantes cuando se usa `-A`:

- Antes: `nmap -A -sV -sC ...`
- Después: `nmap -A ...`

La flag `-A` ya incluye `-sV` (detección de versión) y `-sC` (escaneo de scripts).

### Herramientas de Vulnerabilidades en Paralelo

Aumentados los workers paralelos de 3 a 4 para acomodar sqlmap junto a testssl, whatweb y nikto.

---

## Corrección de Errores

### Corrección de Recursión Infinita

Corregido un bug crítico donde `hasattr(self, "_hyperscan_prescan_ports")` causaba recursión infinita debido a `__getattr__` personalizado en clases Auditor.

**Solución:** Cambiado a `"_hyperscan_prescan_ports" in self.__dict__`.

---

## Documentación

- Actualizado ROADMAP.es.md con características planificadas para v4.2
- Añadido Escaneo de Vulns de Apps Web (sqlmap/ZAP) al roadmap

---

## Próximamente en v4.2

- Integración completa de sqlmap/ZAP para testing comprehensivo de apps web
- Separación de Deep Scan de `scan_host_ports()`
- Paso de datos Red Team → Agentless
- Mejoras de UX del Wizard
- Mejora del log de sesión

---

## Instrucciones de Actualización

```bash
git pull origin main
sudo ./redaudit_install.sh
```

El instalador ahora instalará sqlmap automáticamente.

---

## Métricas de Test (MSI Vector i9-14ª gen, 32GB RAM)

| Fase | Duración | Resultado |
|:-----|:---------|:----------|
| Net Discovery | 191s | 48 hosts |
| HyperScan-First | 331s | 19 puertos |
| nmap Fingerprint | ~16 min | 25 hosts |
| Escaneo Vulns | ~17 min | 16 hosts web |
| **Total** | ~1h01m | 25 activos, 14 hallazgos |
