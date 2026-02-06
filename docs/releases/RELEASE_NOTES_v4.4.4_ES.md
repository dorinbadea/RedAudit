# Notas de la Versión RedAudit v4.4.4

[![View in English](https://img.shields.io/badge/View_in-English-blue.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.4.4/docs/releases/RELEASE_NOTES_v4.4.4.md)

Esta versión se centra en la calidad y la fiabilidad, alcanzando un hito de ~90% de cobertura de código. Incluye pruebas mejoradas para el escaneo SYN, la integración SIEM y la fiabilidad de los informes, asegurando que RedAudit se mantenga estable en entornos de red complejos.

## Mejoras

* **Push Agresivo de Cobertura**:
  * Alcanzado el **~90% de cobertura total de código** (frente al 89%).
  * **Fiabilidad SIEM**: Pruebas ampliadas para `siem.py` que cubren el desglose del risk score, la generación de CEF y el mapeo de severidad por herramienta (Nuclei, TestSSL).
  * **Robustez del Escaneo SYN**: Añadidas pruebas de rutas de fallo para el nuevo escáner SYN basado en Scapy.
  * **Seguridad en Informes**: Reforzado `reporter.py` con pruebas para errores de permisos del sistema de archivos y verificación de artefactos cifrados.
  * **Orquestación Core**: Cobertura mejorada para la lógica de inicialización y conexión en `auditor.py` e `hyperscan.py`.

## Correcciones (del hotfix v4.4.3)

* **Supresión de Ruido en mDNS**: Manejo elegante de los tiempos de espera de mDNS.
* **Verificación Agentless Restaurada**: Corregido el error de pérdida de datos al manejar los nuevos objetos `Host`.
* **Parsing SNMP**: Corregida la sintaxis de regex para una extracción de CIDR/SNMP más segura.

---

**Changelog Completo**: [v4.4.2...v4.4.4](https://github.com/dorinbadea/RedAudit/compare/v4.4.2...v4.4.4)
