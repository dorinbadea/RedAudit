# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](ROADMAP.en.md)

**Audiencia:** Colaboradores, responsables
**Alcance:** Funcionalidades planificadas, capacidades verificadas y conceptos descartados.
**Fuente de verdad:** Estado del código en el repositorio y el historial Git

---

Este documento describe el roadmap técnico, verifica las capacidades ya implementadas y registra los enfoques descartados para RedAudit.

## 1. Roadmap Activo (Futuro y En Progreso)

Estos elementos representan el backlog actual de trabajo planificado o aplazado para la serie v4.x restante.

### v4.14 Gestión de Dependencias (Prioridad: Baja)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Modo de Anclaje de Dependencias** | Hecho (v4.18.8) | Anclaje opcional del toolchain descargado desde GitHub vía `REDAUDIT_TOOLCHAIN_MODE` y overrides. |
| **Evaluación de poetry.lock** | Hecho (v4.18.8) | Añadido `poetry.lock` junto a pip-tools para evaluación y paridad de workflows. |
| **Streaming JSON Report** | Planeado | Escritura incremental para reportes >500MB en redes muy grandes para evitar OOM. |

### Diferido / Backlog Técnico

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Refactorización de auditor.py** | Diferido | Dividir orquestación y lógica de decisión solo si desbloquea tests o corrige defectos. |
| **Distribución PyPI** | Diferido | Publicar `pip install redaudit`. Bloqueado por necesidad de testeo extensivo multiplataforma. |
| **Motor de Plugins** | Diferido | Arquitectura "Plugin-first" para desacoplar el escáner core de las herramientas. |
| **Migración AsyncIO** | Diferido | Migración completa a AsyncIO diferida a v5.0. |
| **Registro central de timeouts** | Diferido | Consolidar timeouts de escáneres en un único punto para ajuste y tests. |
| **Separación de módulo Red Team** | Hecho (v4.18.8) | Separar la lógica Red Team en un módulo dedicado para reducir `net_discovery.py`. |

---

### Funcionalidades Futuras (v5.0.0)

| Funcionalidad | Descripción |
|---|---|
| **Sondas IoT Específicas de Protocolo** | Consultas profundas para protocolos específicos de dispositivos (Tuya, CoAP, propietarios). |
| **Seguimiento de Fugas (Leak Following)** | Expansión automatizada del alcance basada en cabeceras internas filtradas. |
| **Auditoría de Pipeline** | Visualización interactiva del flujo de descubrimiento. |

---

## 2. Hitos Completados (Histórico)

Estos elementos están ordenados cronológicamente (el más reciente primero).

### v4.18.20 Resiliencia de Nuclei y ajuste de UI (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Limite de paralelismo en Nuclei** | Hecho (v4.18.20) | Los timeouts largos de Nuclei ahora limitan los lotes paralelos para evitar timeouts del escaneo completo. |
| **Resincronizacion de idioma UI** | Hecho (v4.18.20) | El UI manager se actualiza cuando cambia el idioma del CLI tras la inicializacion. |
| **Contraste de estado ANSI** | Hecho (v4.18.20) | Las lineas de estado en ANSI ahora aplican el color al texto completo. |

### v4.18.19 Consistencia de UI y Snapshot de Configuracion (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Sincronizacion de idioma UI** | Hecho (v4.18.19) | El idioma del UI manager sigue el idioma del CLI para evitar mezcla EN/ES. |
| **Estilo de lineas en progreso** | Hecho (v4.18.19) | La salida Rich aplica el color de estado a todas las lineas del mensaje. |
| **Campos de snapshot** | Hecho (v4.18.19) | El snapshot de reporte incluye `deep_id_scan`, `trust_hyperscan` y `nuclei_timeout`. |

### v4.18.18 Contraste del Wizard y Enriquecimiento de Bajo Impacto (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Sonda HTTP para Vendor-Only** | Hecho (v4.18.18) | El enriquecimiento Phase 0 sondea HTTP/HTTPS cuando el host solo tiene vendor/MAC y cero puertos abiertos. |
| **Contraste de valores por defecto** | Hecho (v4.18.18) | Las opciones no seleccionadas se muestran en azul y los valores por defecto se resaltan en los prompts. |
| **Timeouts tras split de Nuclei** | Hecho (v4.18.18) | Los lotes divididos reducen el timeout para evitar esperas largas en objetivos lentos. |

### v4.18.17 Claridad de Reportes HyperScan (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Alineacion de resumen HyperScan** | Hecho (v4.18.17) | Las comparativas de HyperScan-First ahora usan solo TCP para coherencia con el CLI. |
| **Conteo UDP en pipeline** | Hecho (v4.18.17) | El resumen del pipeline incluye el total de puertos UDP de HyperScan para visibilidad en informes. |

### v4.13 Resiliencia y Observabilidad (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Reintentos de Host Muerto** | Hecho (v4.13.0) | Nuevo flag CLI `--dead-host-retries` para abandonar hosts tras N timeouts consecutivos. |
| **Detección de Honeypot** | Hecho (v4.9.1) | Etiquetado heurístico (`honeypot`) para hosts con excesivos puertos abiertos (>100). |
| **Etiquetado Sin Respuesta** | Hecho (v4.9.1) | Etiqueta distintiva `no_response` para hosts que fallan el escaneo Nmap. |
| **i18n Estimaciones Nuclei** | Hecho (v4.13.0) | Corregidas estimaciones de tiempo en wizard para perfiles fast/balanced. |

### v4.12 Rendimiento y Calidad de Dato (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Optimización Perfil Nuclei 'Fast'** | Hecho (v4.12.1) | Aumento de velocidad (300 req/s) y tamaño de lote (15) para perfil rápido. |
| **Enriquecimiento Vendor OUI** | Hecho (v4.12.1) | Fallback a API online para vendors desconocidos en topología de red. |
| **Wizard "Express" Clarificado** | Hecho (v4.12.1) | I18n actualizado para indicar explícitamente "Solo Descubrimiento". |
| **Configuración Nuclei Flexible** | Hecho (v4.12.1) | Parámetros `rate_limit` y `batch_size` configurables por perfil y overrideables. |
| **Contadores Razón Escalado** | Hecho (v4.12.1) | Métricas agregadas de por qué se dispararon escaneos profundos (score, ambigüedad). |

### v4.11 Rendimiento y Visibilidad IoT (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Perfiles de Escaneo Nuclei** | Hecho (v4.11.0) | Flag `--profile` (full/balanced/fast) para controlar intensidad y velocidad. |
| **Detección IoT WiZ** | Hecho (v4.11.0) | Sonda UDP especializada (38899) para bombillas inteligentes WiZ. |
| **Expansión Base de Datos OUI** | Hecho (v4.11.0) | Macs actualizadas a ~39k fabricantes (ingesta Wireshark). |
| **Optimización Lotes Nuclei** | Hecho (v4.11.0) | Tamaño de lote reducido (10) y timeouts aumentados (600s) para redes densas. |

### v4.10 Descubrimiento Avanzado (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Consulta SNMP Router** | Hecho (v4.10.0) | Consultar interfaces de router y tablas ARP remotas via `snmpwalk`. |
| **Descubrimiento LLDP** | Hecho (v4.10.0) | Descubrir topología de switch en redes gestionadas via `lldpctl`. |
| **Descubrimiento CDP** | Hecho (v4.10.0) | Parsing de Cisco Discovery Protocol para topologías basadas en Cisco. |
| **Detección Etiquetado VLAN** | Hecho (v4.10.0) | Detectar VLANs etiquetadas 802.1Q en interfaces del host auditor via `ifconfig`/`ip link`. |

### v4.9 Deteccion de Redes Ocultas (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **Descubrimiento de Redes Enrutadas** | Hecho (v4.9.0) | Detectar redes ocultas via parsing de `ip route` e `ip neigh`. |
| **Prompt de Descubrimiento Interactivo** | Hecho (v4.9.0) | El asistente pregunta para incluir redes enrutadas descubiertas en el alcance. |
| **CLI --scan-routed** | Hecho (v4.9.0) | Inclusión automatizada de redes enrutadas para pipelines CI/CD. |
| **Visibilidad Puertos UDP IoT** | Hecho (v4.9.1) | Asegurar que puertos UDP especializados (ej. WiZ 38899) encontrados por HyperScan se incluyan en reportes finales. |
| **Detección de Honeypot** | Hecho (v4.9.1) | Etiquetado heurístico (`honeypot`) para hosts con excesivos puertos abiertos (>100). |
| **Etiquetado Sin Respuesta** | Hecho (v4.9.1) | Etiqueta distintiva `no_response` para hosts que fallan el escaneo Nmap. |

### v4.8 RustScan y Correcciones Instalador (Hecho)

| Funcionalidad | Estado | Descripción |
|---|---|---|
| **RustScan Rango Completo** | Hecho (v4.8.2) | Forzar `-r 1-65535` para escanear todos los puertos en lugar del default top 1000 de RustScan. |
| **Soporte Instalador ARM64** | Hecho (v4.8.3) | Añadida detección ARM64/aarch64 para Raspberry Pi y VMs Apple Silicon. |
| **Toggle Asistente Nuclei** | Hecho (v4.8.1) | Restaurar prompt interactivo de activación de Nuclei en perfil Exhaustivo. |

### v4.7 Integracion HyperScan Masscan (Hecho)

| Caracteristica | Estado | Descripcion |
|---|---|---|
| **Backend Masscan** | Reemplazado (v4.8.0) | `masscan_scanner.py` reemplazado por `RustScan` para mayor velocidad y precision. |
| **Integracion RustScan** | Hecho (v4.8.0) | Nuevo modulo primario para HyperScan. Escaneo de todos los puertos en ~3s. |
| **Fallback Redes Docker** | Hecho (v4.7.1) | Fallback automatico a Scapy cuando Masscan retorna 0 puertos (redes bridge Docker). |
| **Fix Timeout Nuclei** | Hecho (v4.7.2) | Timeout de command_runner aumentado a 600s para Nuclei (era 60s, causando timeouts de batch). |
| **Skip 404 API NVD** | Hecho (v4.7.2) | Omitir reintentos en respuestas 404 (CPE no encontrado). Reduce spam de logs. |

### v4.6 Fidelidad de Escaneo y Control de Tiempo (Hecho)

| Característica | Estado | Descripción |
|---|---|---|
| **Gating de Apps Web por Infraestructura** | Hecho | Omitir sqlmap/ZAP en UIs de infraestructura cuando la evidencia de identidad indica router/switch/AP. |
| **Evidencia de Identidad en Deep Scan** | Hecho | Título/servidor HTTP y tipo de dispositivo evitan deep scan cuando la identidad ya es fuerte. |
| **Sonda HTTP Rápida de Identidad** | Hecho | Sonda HTTP/HTTPS breve en hosts silenciosos para resolver identidad antes. |
| **Informe Parcial de Nuclei** | Hecho | Marcar ejecuciones parciales y registrar lotes con timeout/fallidos en el informe. |
| **Latido por Batch de Nuclei** | Hecho (v4.6.11) | Mantener actualizaciones de progreso durante lotes largos para mostrar actividad y tiempo transcurrido. |
| **Progreso por Objetivos de Nuclei** | Hecho (v4.6.13) | Mostrar avance basado en objetivos dentro de cada batch para evitar barras congeladas. |
| **Estabilidad del progreso de Nuclei** | Hecho (v4.6.15) | Mantener el avance de objetivos sin retrocesos durante reintentos/timeouts. |
| **Endurecimiento de timeouts Nuclei** | Hecho (v4.6.16) | Timeouts adaptativos por lote y divisiones recursivas para reducir ejecuciones parciales. |
| **Contexto de keyring con sudo** | Hecho (v4.6.17) | Preservar el contexto de DBus al cargar credenciales guardadas bajo sudo. |
| **Alineación de informes de hosts** | Hecho (v4.6.15) | Rellenar hosts con nombres/interfaces unificados para consistencia. |
| **Guardia de Origen de Identidad HTTP** | Hecho (v4.6.11) | Tratar títulos solo UPnP como pistas y evitar forzar escaneo web o score de identidad. |
| **Resumen de normalización de objetivos en el wizard** | Hecho (v4.6.13) | Mostrar objetivos normalizados con hosts estimados antes de ejecutar. |
| **Spray de Credenciales SSH** | Hecho (v4.6.18) | Probar todas las credenciales de la lista spray hasta autenticar. |
| **Priorización de Hallazgos** | Hecho (v4.6.19) | Nuevos campos `priority_score` (0-100) y `confirmed_exploitable` para ranking superior de vulnerabilidades. |
| **Detección Clásica de Backdoors** | Hecho (v4.6.19) | Detección automática en banner de `vsftpd 2.3.4`, `UnrealIRCd 3.2.8.1` y otros backdoors. |
| **Puntuación de Confianza de Reporte** | Hecho (v4.6.19) | Score de confianza (`confidence_score` 0.0-1.0) basado en validación cruzada (Nuclei+CVE). |
| **Mejora de Títulos de Hallazgos** | Hecho (v4.6.19) | Títulos más descriptivos ("SSL Hostname Mismatch") en lugar de genéricos. |
| **Contador de Spray en Wizard** | Hecho (v4.6.19) | Visualización `(+N spray)` en el resumen de credenciales guardadas para mayor claridad. |

### v4.4 Cobertura de Código y Estabilidad (Hecho)

| Característica | Estado | Descripción |
|---|---|---|
| **Cobertura Topology 100%** | Hecho (v4.4.5) | Alcanzada cobertura completa de tests para `topology.py`. |
| **Cobertura Updater >94%** | Hecho (v4.4.5) | Endurecido `updater.py` con tests robustos. |
| **Cobertura Proyecto ~89%** | Hecho (v4.4.5) | Cobertura total del proyecto ahora en 88.75% (1619 tests pasando). |
| **Corrección Memory Leak** | Hecho (v4.4.5) | Corregido bucle infinito en mocks de tests. |
| **Targeting basado en Generadores** | Hecho (v4.4.0) | Refactorizado HyperScan para usar generadores lazy. |
| **Informe JSON en Streaming** | Hecho | Optimizado `auditor_scan.py` para evitar materializar listas. |
| **Smart-Throttle (AIMD)** | Hecho (v4.4.0) | Control de congestión adaptativo AIMD en HyperScan. |

### v4.3 Mejoras al Risk Score (Hecho)

| Característica | Estado | Descripción |
|---|---|---|
| **Algoritmo Weighted Maximum Gravity** | Hecho | Refactorizado `calculate_risk_score()` usando CVSS de NVD. |
| **Risk Score Breakdown Tooltip** | Hecho | HTML reports show detailed risk score components on hover. |
| **Identity Score Visualization** | Hecho | HTML reports display color-coded identity_score with tooltip showing identity signals. |
| **Smart-Check CPE Validation** | Hecho | Enhanced Nuclei false positive detection using host CPE data. |
| **HyperScan SYN Mode** | Hecho | Optional scapy-based SYN scanning (`--hyperscan-mode syn`). |
| **PCAP Management Utilities** | Hecho | `merge_pcap_files()`, `organize_pcap_files()`, cleanup. |

### v4.2 Optimizaciones Pipeline (Liberado en m v4.2.0)

Ver [Release Notes](../releases/RELEASE_NOTES_v4.2.0.md) para detalles.

### v4.1 Optimizaciones de Rendimiento (Hecho)

| Característica | Estado | Descripción |
|---|---|---|
| **HyperScan-First Secuencial** | Hecho | Pre-escaneo de 65.535 puertos por host secuencialmente. |
| **Escaneo Vulns Paralelo** | Hecho | nikto/testssl/whatweb concurrentemente por host. |
| **Pre-filtrado Nikto CDN** | Hecho | Omitir Nikto en Cloudflare/Akamai/AWS CloudFront. |
| **Reutilización puertos masscan** | Hecho | Pre-scan usa puertos de masscan si ya estaban descubiertos. |
| **CVE Lookup reordenado** | Hecho | CVE correlation movido después de Vuln Scan + Nuclei. |

### v4.0 Refactorización Arquitectónica (Hecho)

Refactorización interna utilizando el patrón Strangler Fig. Completado en v4.0.0.

### Infraestructura (Prioridad: Alta)

| Característica | Estado | Descripción |
|---|---|---|
| **Consolidación Suite Tests** | Hecho | Refactorizado 199 archivos → 123. 1130 tests al 85%. |

---

## 3. Referencia de Capacidades Verificadas

Referencia de verificación de capacidades clave contra la base de código.

| Capacidad | Versión | Ruta Código / Verificación |
|---|---|---|
| **Descubrimiento Pasivo LLDP** | v4.10.0 | `core/topology.py` (via `tcpdump` & `lldpctl`) |
| **Descubrimiento Pasivo CDP** | v4.10.0 | `core/topology.py` (via `tcpdump`/CISCO-CDP) |
| **Etiquetado VLAN (802.1Q)** | v4.10.0 | `core/topology.py` (via `ip link`/`ifconfig`) |
| **Sonda IoT WiZ (UDP)** | v4.11.0 | `core/udp_probe.py`, `core/auditor.py` |
| **Perfiles Nuclei** | v4.11.0 | `core/nuclei.py`, `core/auditor.py` |
| **Base Datos OUI** | v4.11.0 | `data/manuf` (38k+ vendors) |
| **Descubrimiento Red Enrutada** | v4.9.0 | `core/net_discovery.py` (`ip route`/`ip neigh`) |
| **Integración RustScan** | v4.8.0 | `core/rustscan.py` |
| **Smart-Check** | v4.3.0 | `core/scanner/enrichment.py` (CPE/Lógica Falsos Positivos) |

---

## 4. Conceptos Descartados

Ideas consideradas pero rechazadas para mantener el foco del proyecto.

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **GUI Web (Controlador)** | Incrementa superficie de ataque y peso. RedAudit es una herramienta CLI "headless". |
| **Framework de Explotación** | Fuera de alcance. RedAudit es para *auditoría*, no explotación (como Metasploit). |
| **Soporte Nativo Windows** | Demasiado complejo. Usar WSL2 o Docker. |
| **Generación Informe PDF** | Añade dependencias pesadas. Se prefiere salida JSON/HTML. |
| **Escaneo Distribuido** | Demasiado complejo (FastAPI/Redis). Arquitectura rechazada. |

---

## 5. Contribuir

1. Revisa [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Lee [CONTRIBUTING.md](../CONTRIBUTING.md).
3. Abre una Discusión antes de iniciar grandes funcionalidades.

[Volver al Índice de Documentación](INDEX.md)
