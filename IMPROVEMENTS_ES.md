# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](IMPROVEMENTS.md)

Este documento describe el roadmap técnico, las mejoras arquitectónicas planificadas y los enfoques descartados para RedAudit.

## Roadmap Inmediato (v2.7+)

| Prioridad | Característica | Descripción |
| :--- | :--- | :--- |
| **Alta** | **Soporte IPv6** | Implementar soporte completo `nmap -6` y validación regex IPv6 en el módulo InputSanitizer. |
| **Alta** | **Correlación CVE** | Profundizar el análisis de vulnerabilidades correlacionando versiones identificadas con NVD (más allá de SearchSploit). |
| **Media** | **Análisis Diferencial** | Crear módulo `diff` para comparar dos reportes JSON y resaltar deltas (nuevos puertos/vulns). |
| **Media** | **Proxy Chains** | Soporte nativo para proxies SOCKS5 para facilitar pivoting. |
| **Baja** | **Contenedorización** | Dockerfile oficial y configuración Docker Compose para contenedores de auditoría efímeros. |

## Propuestas Arquitectónicas

### 1. Motor de Plugins Modular

**Estado**: En Consideración
**Concepto**: Desacoplar el escáner principal de las herramientas. Permitir "Plugins" basados en Python para definir nuevos wrappers de herramientas sin modificar la lógica central.
**Beneficio**: Facilita contribución de la comunidad y extensibilidad.

### 2. Escaneo Distribuido (Master/Slave)

**Estado**: Largo plazo
**Concepto**: Separar el Orquestador de los workers de verificación.

- API Central (Master) distribuye objetivos.
- Agentes Remotos (Slaves) ejecutan escaneos y devuelven JSON.

### 3. Configuración Persistente

**Estado**: Planificado
**Concepto**: Permitir configuración de usuario en `~/.redaudit/config.yaml` para anular valores por defecto (eliminando la necesidad de flags CLI repetitivos).

## Hitos Completados

### v2.9.0 (Completado - Diciembre 2025) -> **ACTUAL**

*Enfoque en inteligencia, eficiencia y documentación profesional.*

- [x] **Smart-Check**: Reducción del 90% de falsos positivos en escaneo web.
- [x] **UDP Taming**: Escaneos 50-80% más rápidos mediante estrategia de 3 fases optimizada.
- [x] **Entity Resolution**: Agrupación de dispositivos multi-interfaz (Unified Assets).
- [x] **SIEM Profesional**: Cumplimiento ECS v8.11 y puntuación de riesgo.
- [x] **Documentación Limpia**: Eliminación completa de etiquetas de versión antiguas y estandarización.

### v2.6-v2.8 (Completado)

*Enfoque en seguridad, profesionalismo e integración de herramientas externas.*

- [x] **Inteligencia de Exploits**: Integrado `searchsploit` para búsqueda automática de exploits basada en versiones.
- [x] **Auditoría SSL/TLS**: Integrado `testssl.sh` para análisis criptográfico profundo de servicios HTTPS.
- [x] **Endurecimiento de Seguridad**: Aumentados requisitos de complejidad de contraseñas (12+ chars, mayús/minús, números).
- [x] **Seguridad CI/CD**: Añadido Dependabot (actualizaciones semanales) y CodeQL (análisis estático) a GitHub Actions.
- [x] **Mejoras UX**: Añadidas barras de progreso `rich` con fallback elegante.
- [x] **Documentación**: Añadidos diagramas de arquitectura (Mermaid), matrices de activación y profesionalización de todos los manuales.

### v2.6 (Completado - Diciembre 2025)

*Enfoque en calidad de código, testing y modularización.*

- [x] **Arquitectura Modular**: Refactorizado en estructura de paquete Python
- [x] **Pipeline CI/CD**: GitHub Actions para testing automatizado (Python 3.9-3.12)
- [x] **Suite de Tests**: Expandido a 34 tests automatizados (89% de cobertura)
- [x] **Constantes Nombradas**: Todos los números mágicos reemplazados
- [x] **Compatibilidad hacia atrás**: `redaudit.py` original preservado como wrapper

## Conceptos Descartados

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **GUI Web (Controlador)** | Incrementa superficie de ataque y peso de dependencias. RedAudit está diseñado como herramienta CLI "headless" para automatización. |
| **Explotación Activa** | Fuera de alcance. RedAudit es una herramienta de *auditoría* y *descubrimiento*, no un framework de explotación. |
| **Soporte Nativo Windows** | Demasiado complejo de mantener en solitario por requisitos de sockets raw. Usar WSL2 o Docker. |
| **Generación PDF** | Añade dependencias pesadas (LaTeX/ReportLab). La salida JSON debe ser consumida por herramientas de reporte externas. |

---

## Contribuir

Si deseas contribuir a alguna de estas features:

1. Revisa los [Issues](https://github.com/dorinbadea/RedAudit/issues) existentes.
2. Comenta antes de empezar para evitar duplicación.
3. Lee [CONTRIBUTING.md](https://github.com/dorinbadea/RedAudit/blob/main/CONTRIBUTING.md).
4. Abre una [Discusión](https://github.com/dorinbadea/RedAudit/discussions) para nuevas ideas.

<div align="center">

**Mantenimiento Activo**
*Última actualización: Diciembre 2025*

<sub>Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. En ese caso, considera hacer un fork o contactarme.</sub>

</div>
