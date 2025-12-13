# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](IMPROVEMENTS.md)

Este documento describe el roadmap técnico, las mejoras arquitectónicas planificadas y los enfoques descartados para RedAudit.

## Roadmap Inmediato (v3.1+)

| Prioridad | Característica | Descripción |
| :--- | :--- | :--- |
| **Alta** | **Puertos UDP Configurables** | Añadir flag CLI `--udp-ports N` (rango: 50-500, defecto: 100) para cobertura UDP ajustable. |
| **Media** | **Descubrimiento NetBIOS/mDNS** | Consultas activas de hostname (puerto 137/5353) para mejorar resolución de entidades. |
| **Media** | **Contenedorización** | Dockerfile oficial y configuración Docker Compose para contenedores de auditoría efímeros. |
| **Baja** | **Ampliar Configuración Persistente** | Extender `~/.redaudit/config.json` más allá de la clave NVD (p.ej. hilos por defecto, directorio de salida, rate limits) y añadir importación/exportación YAML opcional. |

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
**Concepto**: Ampliar la configuración de usuario en `~/.redaudit/config.json` para anular valores por defecto (eliminando la necesidad de flags CLI repetitivos). Opcionalmente añadir importación/exportación YAML por comodidad.

## Hitos Completados

### v3.0.1 (Completado - Diciembre 2025) -> **ACTUAL**

*Patch centrado en configuración, endurecimiento de update e higiene documental.*

- [x] **API Key NVD Persistente**: Guardar/leer la clave NVD vía archivo de config + variable de entorno.
- [x] **Verificación del Updater**: El auto-update resuelve el tag publicado y verifica el hash del commit antes de instalar.
- [x] **Instalación testssl.sh fijada**: El instalador fija `testssl.sh` a un tag/commit conocido y lo verifica antes de enlazar.
- [x] **Resiliencia NVD**: Reintentos con backoff en errores transitorios (429/5xx/red).
- [x] **Modo limitado sin root**: `--allow-non-root` permite ejecutar sin sudo (capacidad limitada).

### v3.0.0 (Completado - Diciembre 2025)

*Lanzamiento mayor con capacidades avanzadas.*

- [x] **Soporte IPv6**: Capacidades completas de escaneo para redes IPv6.
- [x] **Validación Magic Bytes**: Detección mejorada de falsos positivos con verificación de firmas.
- [x] **Correlación CVE (NVD)**: Inteligencia profunda de vulnerabilidades via API NIST NVD con caché de 7 días.
- [x] **Análisis Diferencial**: Comparar dos reportes JSON para detectar cambios de red.
- [x] **Proxy Chains (SOCKS5)**: Soporte para pivoting via wrapper proxychains.
- [x] **Auto-Update Mejorado**: Enfoque git clone con verificación y copia a carpeta home.

### v2.9.0 (Completado - Diciembre 2025)

*Enfoque en inteligencia, eficiencia y documentación profesional.*

- [x] **Smart-Check**: Reducción del 90% de falsos positivos en escaneo web.
- [x] **UDP Taming**: Escaneos 50-80% más rápidos mediante estrategia de 3 fases optimizada.
- [x] **Entity Resolution**: Agrupación de dispositivos multi-interfaz (Unified Assets).
- [x] **SIEM Profesional**: Cumplimiento ECS v8.11 y puntuación de riesgo.
- [x] **Documentación Limpia**: Eliminación completa de etiquetas de versión antiguas.

### v2.7-v2.8 (Completado)

*Enfoque en concurrencia, seguridad e integración de herramientas externas.*

- [x] **Deep Scan Adaptativo**: Estrategia de 3 fases (TCP agresivo → UDP prioritario → UDP completo)
- [x] **Captura PCAP Concurrente**: Tráfico capturado durante escaneos
- [x] **Auto-Actualización Segura**: Integración GitHub con reinicio automático
- [x] **Motor Pre-scan**: Descubrimiento rápido asyncio antes de nmap
- [x] **Inteligencia de Exploits**: Integración SearchSploit para versiones detectadas
- [x] **Análisis SSL/TLS**: Escaneo profundo TestSSL.sh
- [x] **Endurecimiento de Seguridad**: Requisitos de contraseña fuerte (12+ chars)
- [x] **Seguridad CI/CD**: Dependabot + análisis estático CodeQL
- [x] **Mejoras UX**: Barras de progreso rich con fallback elegante

### v2.6 (Completado)

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

---

**Mantenimiento Activo** | *Última actualización: Diciembre 2025*

*Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. En ese caso, considera hacer un fork o contactarme.*
