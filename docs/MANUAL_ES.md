# Manual de Usuario de RedAudit

**Versión**: 2.5
**Fecha**: 2025-12-07
**Nivel Objetivo**: Pentester Profesional / SysAdmin

---

## 📑 Índice (TOC)
1. [Introducción](#1-introducción)
2. [Entorno Soportado](#2-entorno-soportado)
3. [Instalación](#3-instalación)
4. [Inicio Rápido](#4-inicio-rápido)
5. [Configuración Profunda](#5-configuración-profunda)
    - [Concurrencia e Hilos](#concurrencia-e-hilos)
    - [Rate Limiting (Sigilo)](#rate-limiting-sigilo)
    - [Cifrado](#cifrado)
6. [Lógica de Escaneo](#6-lógica-de-escaneo)
7. [Guía de Descifrado](#7-guía-de-descifrado)
8. [Monitorización y Heartbeat](#8-monitorización-y-heartbeat)
9. [Script de Verificación](#9-script-de-verificación)
10. [FAQ (Preguntas Frecuentes)](#10-faq-preguntas-frecuentes)
11. [Glosario](#11-glosario)
12. [Aviso Legal](#12-aviso-legal)

---

## 1. Introducción
RedAudit es un framework de reconocimiento automatizado diseñado para agilizar el flujo de `Descubrimiento` → `Enumeración` → `Evaluación de Vulnerabilidades`. Envuelve herramientas estándar de la industria (`nmap`, `whatweb`, `tcpdump`) en un modelo de concurrencia robusto basado en Python, añadiendo capas de resiliencia (heartbeats, reintentos) y seguridad (cifrado, sanitización).

## 2. Entorno Soportado
- **SO**: Kali Linux (Preferido), Debian 10+, Ubuntu 20.04+.
- **Privilegios**: Acceso **Root** (`sudo`) obligatorio para:
    - Escaneo SYN (`nmap -sS`).
    - Detección de SO (`nmap -O`).
    - Captura de paquetes crudos (`tcpdump`).
- **Python**: 3.8 o superior.

## 3. Instalación
RedAudit usa un script instalador consolidado que gestiona dependencias (apt) y configuración.

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
source ~/.bashrc  # Activa el alias
```

**Dependencias instaladas:**
- `nmap`, `python3-nmap` (Escaneo núcleo)
- `python3-cryptography` (Cifrado de reportes)
- `whatweb`, `nikto`, `tcpdump`, `tshark` (Enriquecimiento opcional)

## 4. Inicio Rápido
Ejecuta `redaudit` para iniciar el asistente interactivo.

**Ejemplo de Sesión:**
```text
? Select network: 192.168.1.0/24
? Select scan mode: NORMAL
? Enter number of threads [1-16]: 6
? Enable Web Vulnerability scans? [y/N]: y
? Enable Web Vulnerability scans? [y/N]: y
? Encrypt reports with password? [y/N]: y
```

## 5. Configuración Profunda

### Concurrencia e Hilos
RedAudit utiliza un **Pool de Hilos** (`concurrent.futures.ThreadPoolExecutor`) para escanear hosts en paralelo.
- **Naturaleza**: Son **Hilos Python**, no procesos. Comparten memoria y estado global, pero dado que Nmap es un subproceso intensivo en E/S, el threading es altamente eficiente.
- **Ajuste**:
    - **1-4 Hilos**: Modo sigilo. Úsalo en redes estrictamente monitorizadas o switches antiguos susceptibles a congestión.
    - **6-10 Hilos (Defecto)**: Equilibrado para LANs estándar.
    - **12-16 Hilos**: Agresivo. Adecuado para CTFs o redes modernas robustas. Superar 16 hilos suele tener retornos decrecientes debido al propio paralelismo interno de Nmap.

### Rate Limiting (Sigilo)
Para evadir heurísticas de IDS basadas en frecuencia de conexión, RedAudit implementa **Rate Limiting a nivel de Aplicación**.
- **Parámetro**: `rate_limit_delay` (segundos).
- **Implementación**: Un `time.sleep(DELAY)` forzado se ejecuta antes de que un hilo trabajador inicie una nueva tarea de host.
- **Impacto**:
    - **0s**: Velocidad máxima (Fire-and-forget).
    - **2s**: Añade un enfriamiento de 2 segundos entre inicios de host. En una subred de 100 hosts con 10 hilos, esto dispersa significativamente las ráfagas de paquetes SYN.
    - **>10s**: "Low and Slow". Aumenta drásticamente el tiempo de escaneo pero elimina virtualmente la detección por ráfagas simples.

### Cifrado
RedAudit trata los datos de los reportes como material sensible.
- **Estándar**: **Fernet** (Cumple especificación).
    - **Cifrado**: AES-128 en modo CBC.
    - **Firma**: HMAC-SHA256.
    - **Validación**: Token con timestamp (TTL ignorado por defecto).
- **Derivación de Clave**:
    - **Algoritmo**: PBKDF2HMAC (SHA-256).
    - **Iteraciones**: 480,000 (supera la recomendación OWASP de 310,000).
    - **Salt**: 16 bytes aleatorios, guardados en archivo `.salt`.
- **Degradación Graceful** (v2.5): Si `python3-cryptography` no está disponible, el cifrado se desactiva automáticamente con avisos claros. No se muestran prompts de contraseña.
- **Permisos de Archivo** (v2.5): Todos los reportes (cifrados y planos) usan permisos seguros (0o600 - solo lectura/escritura del propietario).
- **Modo No Interactivo** (v2.5): El flag `--encrypt-password` permite especificar la contraseña en modo no interactivo. Si se omite, se genera una contraseña aleatoria que se muestra en la salida.

## 6. Lógica de Escaneo
1.  **Descubrimiento**: Barrido ICMP Echo (`-PE`) + ARP (`-PR`) para mapear hosts vivos.
2.  **Enumeración**: Escaneos Nmap paralelos basados en el modo.
3.  **Deep Scan Adaptativo (Automático)**:
    - **Disparadores**: Se activa automáticamente si un host:
        - Tiene más de 8 puertos abiertos
        - Tiene servicios sospechosos (socks, proxy, vpn, tor, nagios, etc.)
        - Tiene 3 o menos puertos abiertos
        - Tiene puertos abiertos pero no se detectó información de versión
    - **Estrategia (2 Fases)**:
        1.  **Fase 1**: `nmap -A -sV -Pn -p- --open --version-intensity 9` (TCP Agresivo).
            - *Chequeo*: Si encuentra MAC/SO, se detiene aquí y omite la Fase 2.
        2.  **Fase 2**: `nmap -O -sSU -Pn -p- --max-retries 2` (UDP + SO de respaldo, solo si la Fase 1 no obtuvo identidad).
    - **Resultado**: Datos guardados en `host.deep_scan`, incluyendo `mac_address`, `vendor`, y flag `phase2_skipped`.

4.  **Captura de Tráfico**:
    - Como parte del proceso de **Deep Scan**, si `tcpdump` está presente, captura un fragmento (50 paquetes/15s) del tráfico del host.
    - **Salida**:
        - Guarda archivos `.pcap` en el directorio de reportes.
        - Si `tshark` está instalado, incrusta un resumen de texto en `host.deep_scan.pcap_capture`.

## 7. Guía de Descifrado
Los reportes cifrados (`.json.enc`, `.txt.enc`) son ilegibles sin la contraseña y el archivo `.salt`.

**Uso:**
```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```
1. El script encuentra `reporte.salt` en el mismo directorio.
2. Pide la contraseña.
3. Deriva la clave e intenta descifrar.
4. Genera `reporte.decrypted.json` o `reporte.json` (si no hay conflicto).

## 8. Monitorización y Heartbeat
Los escaneos largos (ej: rangos de puertos completos en redes lentas) pueden parecer "cuelgues".
- **Hilo Heartbeat**: Revisa la marca de tiempo `self.last_activity` cada 60s.
- **Estados**:
    - **Activo**: Actividad < hace 60s. Sin salida.
    - **Ocupado**: Actividad < hace 300s. Log de advertencia.
    - **Silencioso**: Actividad > hace 300s.
        - Mensaje: *"Nmap sigue ejecutándose; esto es normal en hosts lentos o filtrados."*
        - **Acción**: NO abortes. Los escaneos profundos pueden tomar 8-10 minutos en hosts con firewall.
- **Logs**: Revisa `~/.redaudit/logs/` para depuración detallada.

## 9. Script de Verificación
Asegura que tu despliegue está limpio y sin corrupciones.
```bash
bash redaudit_verify.sh
```
Comprueba:
- Rutas de binarios.
- Disponibilidad de módulos Python (`cryptography`, `nmap`).
- Configuración de alias.
- Presencia de herramientas opcionales.

## 10. FAQ (Preguntas Frecuentes)
**P: ¿Por qué error "Encryption missing"?**
R: Probablemente saltaste la instalación de dependencias. Ejecuta `sudo apt install python3-cryptography`.

**P: ¿Puedo escanear sobre VPN?**
R: Sí, RedAudit detecta interfaces VPN tun0/tap0 automáticamente.

**P: ¿Es seguro para producción?**
R: Sí, si se configura responsablemente (Hilos < 5, Rate Limit > 1s). Ten siempre autorización.

**P: ¿Por qué encuentro pocos puertos?**
R: El objetivo puede estar filtrando paquetes SYN. RedAudit intentará un Deep Scan automáticamente para intentar sortear esto.

## 11. Glosario
- **Deep Scan**: Escaneo de respaldo automático con flags agresivos de Nmap para sondear hosts "silenciosos".
- **Fernet**: Primitiva de cifrado simétrico que asegura seguridad e integridad de 128 bits.
- **Heartbeat**: Hilo de monitorización en segundo plano que asegura la salud del proceso.
- **PBKDF2**: *Password-Based Key Derivation Function 2*. Hace que el crackeo de contraseñas sea lento.
- **Ports Truncated**: Optimización donde listas >50 puertos se resumen para mantener los reportes legibles.
- **Rate Limit**: Retardo artificial introducido para reducir el ruido en la red.
- **Salt**: Dato aleatorio combinado con la contraseña para crear una clave de cifrado única.

## 12. Aviso Legal
Esta herramienta es **únicamente para auditorías de seguridad autorizadas**. El uso sin consentimiento escrito del propietario de la red es ilegal bajo jurisdicciones de responsabilidad estricta. Los autores no aceptan responsabilidad por daños o uso no autorizado.

### Licencia

RedAudit se distribuye bajo la **GNU General Public License v3.0 (GPLv3)**.  
Consulta el archivo raíz [LICENSE](../LICENSE) para más detalles.
