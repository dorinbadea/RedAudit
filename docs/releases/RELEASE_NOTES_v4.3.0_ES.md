# Notas de Lanzamiento RedAudit v4.3.0

[![View in English](https://img.shields.io/badge/EN-English-blue)](./RELEASE_NOTES_v4.3.0.md)

**Fecha de Lanzamiento**: 2026-01-07

## Destacados

Esta versión introduce **Enterprise Risk Scoring V2** para una evaluación de riesgos precisa basada en configuraciones y **Optimizaciones de Escaneo Docker** (H2) significativas para análisis profundo de contenedores, transformando RedAudit en un verdadero motor de decisión de auditoría.

---

## Nuevas Características

### Enterprise Risk Scoring V2

El motor de cálculo de riesgo ha sido renovado para tratar los **Hallazgos de Configuración** (de Nikto, Nuclei, Zap) como factores de riesgo primarios junto a los CVEs.

- **Comportamiento previo**: La puntuación dependía mucho de CVSS/CVEs. Un host con cero CVEs pero un panel de admin expuesto (Hallazgo Crítico) a menudo recibía una puntuación baja.
- **Nuevo comportamiento**: Los hallazgos con severidad `high` o `critical` impactan directamente el Bonus de Densidad y el Multiplicador de Exposición. Un host con fallos de configuración críticos ahora puntúa correctamente en el rango 80-100 (Alto/Crítico), asegurando una priorización precisa.

### Optimización Docker y Deep Scan (H2)

Hemos optimizado la fase de "Deep Scan" para manejar mejor contenedores Docker y servicios efímeros comunes en stacks modernos:

- **Nikto Desencadenado**: Eliminadas las restricciones de tuning por defecto (`-Tuning x`) y aumentado el timeout a 5 minutos (`300s`). Esto asegura que Nikto complete chequeos completos en apps web complejas.
- **Nuclei Expandido**: El escáner ahora procesa hallazgos con `severity="low"`, capturando fugas de información críticas (ej: logs expuestos, páginas de estado, config .git) que anteriormente eran filtradas.

### Modo SYN de HyperScan

Nuevo modo de escaneo de puertos basado en SYN para usuarios privilegiados:

- **Velocidad**: ~10x más rápido que escaneos connect.
- **Uso**: Seleccionado automáticamente al ejecutar como root con scapy instalado, o forzar con `--hyperscan-mode syn`.

---

## Mejoras

### Reducción de Ruido

Limpiada la salida de errores de `arp-scan` y `scapy` (advertencias redundantes de "Mac address to reach destination not found") para una experiencia de terminal profesional y sin ruido.

### Visualización de Identidad

Los informes HTML ahora codifican por color el `identity_score` para mostrar claramente qué hosts están plenamente identificados vs. los que requieren revisión manual.

### Gestión de PCAP

Limpieza y organización automatizada de artefactos de captura de paquetes.

---

## Correcciones de Errores

### Validación Smart-Check

Filtrado de falsos positivos mejorado usando validación cruzada CPE.

### Regresión en Lógica de Riesgo

Corregida una regresión crítica donde hallazgos no-CVE resultaban en una puntuación de riesgo 0.

---

## Instalación

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
```

---

## Enlaces

- [Registro de Cambios Completo](../../ES/CHANGELOG_ES.md)
- [Documentación](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
