# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](IMPROVEMENTS.md)

Este documento describe el roadmap técnico, las mejoras arquitectónicas planificadas y los enfoques descartados para RedAudit.

## Roadmap Inmediato (v3.1+)

| Prioridad | Característica | Descripción |
| :--- | :--- | :--- |
| **Alta** | **Descubrimiento de Topología de Red** | Reconocimiento pre-scan con escaneo ARP, detección de VLANs, mapeo de gateways y visualización de topología L2. Usa `arp-scan`, `nmap broadcast scripts` y parsing CDP/LLDP. |
| **Alta** | **Puertos UDP Configurables** | Añadir flag CLI `--udp-ports N` (rango: 50-500, defecto: 100) para cobertura UDP ajustable. |
| **Media** | **Descubrimiento NetBIOS/mDNS** | Consultas activas de hostname (puerto 137/5353) para mejorar resolución de entidades. |
| **Media** | **Contenedorización** | Dockerfile oficial y configuración Docker Compose para contenedores de auditoría efímeros. |
| **Baja** | **Ampliar Configuración Persistente** | Extender `~/.redaudit/config.json` más allá de la clave NVD (p.ej. hilos por defecto, directorio de salida, rate limits) y añadir importación/exportación YAML opcional. |

### Descubrimiento de Topología de Red (Objetivo v4.0)

**Objetivo**: Reconocimiento rápido pre-scan para mapear la arquitectura de red antes del escaneo profundo.

| Capacidad | Herramienta | Salida |
| :--- | :--- | :--- |
| **Descubrimiento L2** | `arp-scan --localnet` | Direcciones MAC + vendor OUI |
| **Detección de VLAN** | `nmap --script broadcast-dhcp-discover,broadcast-arp` | IDs de VLAN, servidores DHCP |
| **Mapeo de Gateway** | `traceroute` + análisis de ICMP redirect | Rutas de routers, detección NAT |
| **Topología L2** | Parsing CDP/LLDP via `tcpdump -nn -v -c 50 ether proto 0x88cc` | Relaciones switch/puerto |
| **Redes Ocultas** | Detección de anomalías ARP + análisis de tabla de rutas | Subredes mal configuradas |

**Opciones CLI**:

```bash
redaudit --topology-only 192.168.0.0/16      # Solo escaneo de topología
redaudit --with-topology --target 10.0.0.0/8 # Integrado con auditoría completa
```

## Propuestas Arquitectónicas

### 1. Motor de Plugins Modular

**Estado**: En Consideración
**Concepto**: Desacoplar el escáner principal de las herramientas. Permitir "Plugins" basados en Python para definir nuevos wrappers de herramientas sin modificar la lógica central.
**Beneficio**: Facilita contribución de la comunidad y extensibilidad.

### 2. Escaneo Distribuido (Coordinador/Workers)

**Estado**: Largo plazo
**Concepto**: Separar el Orquestador de los workers de verificación.

- API Central (Coordinador) distribuye objetivos.
- Workers remotos (Nodos) ejecutan escaneos y devuelven JSON.

### 3. Configuración Persistente

**Estado**: Planificado
**Concepto**: Ampliar la configuración de usuario en `~/.redaudit/config.json` para anular valores por defecto (eliminando la necesidad de flags CLI repetitivos). Opcionalmente añadir importación/exportación YAML por comodidad.

## Hitos Completados

### v3.0.4 (Completado - Diciembre 2025) -> **ACTUAL**

*Patch centrado en mejorar la claridad del límite de hosts en modo interactivo y alinear documentación.*

- [x] **Límite de hosts por defecto = todos**: El prompt interactivo escanea todos los hosts encontrados por defecto (ENTER = todos / all).
- [x] **Texto más claro**: Los números significan un límite máximo global de hosts (no un selector de host/IP).

### v3.0.3 (Completado - Diciembre 2025)

*Patch centrado en transparencia del auto-update y preservación de idioma.*

- [x] **Idioma preservado en actualización**: El auto-update mantiene el idioma instalado (ej: Español sigue en Español).
- [x] **Salida de update más explícita**: Muestra ref/commit objetivo, cambios de ficheros (+/~/-) y pasos claros de instalación/backup.

### v3.0.2 (Completado - Diciembre 2025)

*Patch centrado en pulido del CLI, claridad de reportes y correlación CVE más segura.*

- [x] **Salida CLI thread-safe**: Evita líneas intercaladas y cortes a mitad de palabra.
- [x] **Mejoras de UX en Español**: Traducciones completadas para mensajes de estado/progreso.
- [x] **Visibilidad de PCAP**: Resumen final muestra contador de PCAP; reporte TXT incluye la ruta del PCAP si se captura.
- [x] **Seguridad en enriquecimiento NVD**: Evita CPEs comodín cuando la versión es desconocida; corrige mensajes sobre el origen de la API key.

### v3.0.1 (Completado - Diciembre 2025)

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
- [x] **Captura PCAP Concurrente**: Tráfico capturado durante escaneos profundos
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
- [x] **Suite de Tests**: Ampliación de tests automatizados e introducción de reporting de cobertura en CI (reportado por CI, sin fijar números aquí)
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
