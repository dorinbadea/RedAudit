# Manual de Usuario de RedAudit v2.7.0

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](MANUAL_EN.md)

**Versión**: 2.7.0  
**Audiencia Objetivo**: Analistas de Seguridad, Pentesters, Administradores de Sistemas  
**Licencia**: GPLv3

---

## Tabla de Contenidos

1. [Introducción](#1-introducción)
2. [Instalación](#2-instalación)
3. [Arquitectura](#3-arquitectura)
4. [Herramientas Externas](#4-herramientas-externas)
5. [Modos de Escaneo](#5-modos-de-escaneo)
6. [Flujo de Escaneo](#6-flujo-de-escaneo)
7. [Cifrado](#7-cifrado)
8. [Monitorización](#8-monitorización)
9. [Descifrado de Reportes](#9-descifrado-de-reportes)
10. [Solución de Problemas](#10-solución-de-problemas)
11. [Glosario](#11-glosario)
12. [Aviso Legal](#12-aviso-legal)

---

## 1. Introducción

RedAudit es una herramienta automatizada de auditoría de red diseñada para sistemas Kali Linux y basados en Debian. Orquesta múltiples herramientas de seguridad (nmap, whatweb, nikto, testssl.sh, searchsploit, y más) a través de un flujo de trabajo inteligente que se adapta a los servicios descubiertos.

**Características Clave:**

- Detección automática de servicios y escaneo profundo dirigido
- **Motor pre-scan asyncio** para descubrimiento rápido de puertos (v2.7)
- Inteligencia de exploits vía integración con ExploitDB
- Análisis de vulnerabilidades SSL/TLS
- Generación de reportes cifrados (AES-128 + PBKDF2)
- **Salida JSON compatible con SIEM** (v2.7)
- Monitorización de progreso con sistema heartbeat
- Soporte bilingüe (Inglés/Español)

---

## 2. Instalación

### Requisitos del Sistema

| Requisito | Mínimo |
|:----------|:-------|
| **SO** | Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS |
| **Python** | 3.9+ |
| **Privilegios** | Root/Sudo (requerido para acceso raw sockets) |

### Instalación Rápida

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### Activación del Shell

| Distribución | Shell | Comando |
|:-------------|:------|:--------|
| Kali Linux (2020.3+) | Zsh | `source ~/.zshrc` |
| Debian / Ubuntu / Parrot | Bash | `source ~/.bashrc` |

---

## 3. Arquitectura

RedAudit v2.6 está organizado como un paquete Python modular:

| Módulo | Propósito |
|:-------|:----------|
| `redaudit/core/auditor.py` | Orquestador principal, gestión de hilos |
| `redaudit/core/scanner.py` | Integración Nmap, deep scans, enriquecimiento |
| `redaudit/core/prescan.py` | Descubrimiento rápido de puertos asyncio (v2.7) |
| `redaudit/core/crypto.py` | Cifrado (derivación de claves PBKDF2, Fernet) |
| `redaudit/core/network.py` | Detección de interfaces de red |
| `redaudit/core/reporter.py` | Generación de reportes JSON/TXT + compatibilidad SIEM |
| `redaudit/utils/constants.py` | Constantes de configuración |
| `redaudit/utils/i18n.py` | Cadenas de internacionalización |

**Invocación:**

```bash
# Usando alias (después de instalar)
sudo redaudit

# Usando módulo Python
sudo python3 -m redaudit --help
```

---

## 4. Herramientas Externas

RedAudit integra 11 herramientas de seguridad externas. Cada una se activa bajo condiciones específicas:

### Matriz de Activación de Herramientas

| Herramienta | Condición de Activación | Modo de Escaneo | Ubicación en Salida |
|:------------|:------------------------|:----------------|:--------------------|
| **nmap** | Siempre | Todos | `host.ports[]` |
| **searchsploit** | Servicio tiene versión detectada | Todos | `ports[].known_exploits` |
| **whatweb** | Puerto HTTP/HTTPS detectado | Todos | `vulnerabilities[].whatweb` |
| **nikto** | Puerto HTTP/HTTPS detectado | Solo Completo | `vulnerabilities[].nikto_findings` |
| **curl** | Puerto HTTP/HTTPS detectado | Todos | `vulnerabilities[].curl_headers` |
| **wget** | Puerto HTTP/HTTPS detectado | Todos | `vulnerabilities[].wget_headers` |
| **openssl** | Puerto HTTPS detectado | Todos | `vulnerabilities[].tls_info` |
| **testssl.sh** | Puerto HTTPS detectado | Solo Completo | `vulnerabilities[].testssl_analysis` |
| **tcpdump** | Durante Deep Scan | Todos (si activado) | `deep_scan.pcap_capture` |
| **tshark** | Tras captura tcpdump | Todos (si activado) | `deep_scan.pcap_capture.tshark_summary` |
| **dig** | Tras escaneo de puertos | Todos | `host.dns.reverse` |
| **whois** | Solo IPs públicas | Todos | `host.dns.whois_summary` |

### Flujo de Activación

```text
Descubrimiento (nmap -sn)
    │
    ▼
Escaneo de Puertos (nmap -sV)
    │
    ├── ¿Servicio tiene versión? ──▶ searchsploit
    │
    ├── ¿HTTP/HTTPS detectado? ──▶ whatweb, curl, wget
    │   └── ¿Modo Completo? ──▶ nikto
    │
    ├── ¿HTTPS detectado? ──▶ openssl
    │   └── ¿Modo Completo? ──▶ testssl.sh
    │
    └── ¿Deep Scan activado?
        ├── tcpdump (captura tráfico)
        └── tshark (resumen protocolo)
    │
    ▼
Enriquecimiento: dig (DNS reverso), whois (IPs públicas)
```

---

## 5. Modos de Escaneo

| Modo | Descripción | Caso de Uso |
|:-----|:------------|:------------|
| **Rápido** | Solo descubrimiento (`nmap -sn`) | Enumeración rápida de hosts |
| **Normal** | Puertos top + versiones de servicio | Auditoría de seguridad estándar |
| **Completo** | Puertos completos + scripts + nikto + testssl | Test de penetración exhaustivo |

### Opciones CLI

```bash
# No interactivo con modo específico
sudo python3 -m redaudit --target 192.168.1.0/24 --mode completo

# Ajustar concurrencia con rate-limiting jitter (v2.7)
sudo python3 -m redaudit --threads 4 --rate-limit 2

# Habilitar pre-scan para descubrimiento rápido (v2.7)
sudo python3 -m redaudit --target 192.168.1.0/24 --prescan
```

---

## 6. Flujo de Escaneo

### Fase 1: Descubrimiento

Barrido ICMP Echo + ARP para identificar hosts vivos.

### Fase 2: Enumeración de Puertos

Escaneos paralelos de nmap basados en el modo seleccionado.

### Fase 3: Deep Scan Adaptativo

Se activa automáticamente cuando un host:

- Tiene más de 8 puertos abiertos
- Tiene servicios sospechosos (socks, proxy, vpn, tor, nagios)
- Tiene 3 o menos puertos abiertos
- Tiene puertos abiertos pero sin información de versión

**Estrategia 2-Fases:**

1. **Fase 1**: `nmap -A -sV -Pn -p- --version-intensity 9`
   - Si se encuentra MAC/SO → Omitir Fase 2
2. **Fase 2**: `nmap -O -sSU -Pn -p- --max-retries 2`
   - UDP + SO de respaldo

### Fase 4: Captura de Tráfico

Si `tcpdump` está disponible, captura 50 paquetes (15s) durante el Deep Scan.
Si `tshark` está disponible, genera resumen de protocolos.

### Fase 5: Enriquecimiento

- **dig**: Búsqueda DNS inversa para todos los hosts
- **whois**: Información de propiedad solo para IPs públicas

---

## 7. Cifrado

### Especificación

| Parámetro | Valor |
|:----------|:------|
| **Algoritmo** | AES-128-CBC (Fernet) |
| **Derivación de Clave** | PBKDF2HMAC-SHA256 |
| **Iteraciones** | 480,000 (excede recomendación OWASP 310,000) |
| **Salt** | 16 bytes aleatorios por sesión |
| **Mínimo Contraseña** | 12 caracteres + complejidad |
| **Permisos de Archivo** | 0o600 (lectura/escritura solo dueño) |

### Uso

```bash
# Interactivo - solicita contraseña
sudo python3 -m redaudit --encrypt

# No interactivo - especificar contraseña
sudo python3 -m redaudit --encrypt --encrypt-password "MiPassSegura123"
```

---

## 8. Monitorización

### Sistema Heartbeat

Un hilo en segundo plano monitoriza el progreso del escaneo cada 60 segundos:

| Estado | Condición | Acción |
|:-------|:----------|:-------|
| Activo | Actividad < 60s | Operación normal |
| Ocupado | 60s < Actividad < 300s | Log de advertencia |
| Silencioso | Actividad > 300s | Alerta (NO abortar) |

**Logs**: `~/.redaudit/logs/redaudit_YYYYMMDD.log`

---

## 9. Descifrado de Reportes

Los reportes cifrados (`.json.enc`, `.txt.enc`) requieren la contraseña y el archivo `.salt`.

```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

1. Localiza `reporte.salt` en el mismo directorio
2. Solicita contraseña
3. Deriva clave y descifra
4. Genera `reporte.decrypted.json` de salida

---

## 10. Solución de Problemas

| Problema | Causa | Solución |
|:---------|:------|:---------|
| "Encryption missing" | Dependencia faltante | `sudo apt install python3-cryptography` |
| Pocos puertos encontrados | Host filtrando paquetes | Deep Scan automático intentará evadir |
| Escaneo parece congelado | Red lenta/filtrada | Revisar logs heartbeat; esperar 8-10 min |
| VPN no detectada | Nombre de interfaz | RedAudit autodetecta tun0/tap0 |

**Script de verificación:**

```bash
bash redaudit_verify.sh
```

---

## 11. Glosario

| Término | Definición |
|:--------|:-----------|
| **Deep Scan** | Escaneo agresivo automático para hosts con datos incompletos |
| **Fernet** | Cifrado simétrico (AES-128-CBC + HMAC-SHA256) |
| **Heartbeat** | Hilo de fondo monitorizando salud del proceso |
| **Jitter** | Varianza aleatoria (±30%) añadida al rate-limiting para evasión de IDS (v2.7) |
| **PBKDF2** | Función de Derivación de Clave Basada en Contraseña 2 |
| **Pre-scan** | Descubrimiento rápido de puertos basado en asyncio antes de nmap (v2.7) |
| **Rate Limit** | Retardo artificial entre operaciones de escaneo |
| **Salt** | Bytes aleatorios combinados con contraseña para clave única |
| **SIEM** | Sistema de Gestión de Información y Eventos de Seguridad |

---

## 12. Aviso Legal

Esta herramienta es **únicamente para auditorías de seguridad autorizadas**.

El uso sin consentimiento escrito del propietario de la red es ilegal. Los autores no aceptan responsabilidad por uso no autorizado o daños resultantes.

### Licencia

RedAudit se distribuye bajo la **GNU General Public License v3.0 (GPLv3)**.  
Ver [LICENSE](../LICENSE) para términos completos.
