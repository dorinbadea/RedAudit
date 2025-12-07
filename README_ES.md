<div align="center">
  <img src="assets/header.png" alt="RedAudit Banner" width="100%">

  <br>

  [ 🇬🇧 English ](README.md) | [ 🇪🇸 Español ](README_ES.md)

  <br>

  [![Versión](https://img.shields.io/badge/versión-2.5-blue.svg)](https://github.com/dorinbadea/RedAudit)
  ![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
  ![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
</div>

<br>

# 🦅 RedAudit v2.5

## 1. 📋 Descripción General
**RedAudit** es una herramienta de auditoría de red interactiva y automatizada diseñada para **Kali Linux** y sistemas basados en Debian. Optimiza el proceso de reconocimiento combinando el descubrimiento de red, escaneo de puertos y evaluación de vulnerabilidades en un flujo de trabajo CLI único y cohesivo.

A diferencia de simples scripts "wrapper", RedAudit gestiona la concurrencia, agregación de datos y generación de reportes (JSON/TXT) mediante lógica robusta en Python, ofreciendo fiabilidad de grado profesional y trazabilidad.

## 2. ✨ Características
- **CLI Interactiva y No Interactiva**: Menú guiado o argumentos completos de línea de comandos para automatización
- **Descubrimiento Inteligente**: Auto-detecta interfaces y subredes locales usando comandos `ip`
- **Escaneo Multimodo**:
    - **RÁPIDO (FAST)**: Barrido ICMP (`-sn`) para detección rápida de hosts vivos
    - **NORMAL**: Puertos principales + Detección de Versiones (`-sV`)
    - **COMPLETO (FULL)**: Todos los puertos, detección de SO (`-O`), Scripts (`-sC`) y escaneo web
- **Deep Scan Adaptativo**: Motor inteligente de 2 fases (TCP Agresivo → UDP/OS Fallback) que maximiza velocidad y datos
- **Detección Vendor/MAC**: Extrae información de hardware incluso en escaneos parciales
- **Análisis de Tráfico**: Micro-capturas opcionales (`tcpdump`) para analizar el comportamiento del objetivo
- **Reconocimiento Web**: Integra `whatweb`, `nikto`, `curl` y `openssl` para servicios web
- **Resiliencia**: Monitor de actividad (heartbeat) en segundo plano para evitar bloqueos silenciosos
- **Listo para Automatización**: Soporte completo CLI para scripting e integración CI/CD

## 3. 🔒 Características de Seguridad (Mejorado en v2.5)
RedAudit v2.5 introduce un endurecimiento de seguridad de grado empresarial:
- **Sanitización de Entrada Endurecida**: Todas las entradas validadas por tipo, longitud y formato
  - Validación de tipo (solo `str` aceptado)
  - Límites de longitud (1024 chars para IPs/hostnames, 50 para CIDR)
  - Eliminación automática de espacios en blanco
  - Validación regex estricta (`^[a-zA-Z0-9\.\-\/]+$`)
  - Sin inyección de shell (usa `subprocess.run` con listas)
- **Reportes Cifrados**: Cifrado opcional **AES-128 (Fernet)** con PBKDF2-HMAC-SHA256 (480,000 iteraciones)
- **Permisos de Archivo Seguros**: Todos los reportes usan permisos 0o600 (solo lectura/escritura del propietario)
- **Manejo Graceful de Cryptography**: Avisos claros si el cifrado no está disponible, sin prompts de contraseña
- **Seguridad de Hilos**: Uso de `ThreadPoolExecutor` con mecanismos de bloqueo adecuados para E/S concurrente
- **Rate Limiting**: Retardos `time.sleep()` configurables para mitigar la saturación de red y detección por IDS
- **Logging de Auditoría**: Logs rotativos exhaustivos (máx 10MB, 5 copias) almacenados en `~/.redaudit/logs/`

[→ Documentación de Seguridad Completa](docs/SECURITY.md)

## 4. 📦 Requisitos y Dependencias
Diseñado para **Kali Linux**, **Debian** o **Ubuntu**.
Requiere privilegios de `root` o `sudo` para detección de SO y captura de paquetes crudos.

**Núcleo (Requerido):**
- `nmap` (Network Mapper)
- `python3-nmap` (Bindings de Python)
- `python3-cryptography` (Para cifrado)

**Recomendado (Enriquecimiento):**
- `whatweb`, `nikto` (Escaneo web)
- `tcpdump`, `tshark` (Captura de tráfico)
- `curl`, `wget`, `openssl` (Análisis HTTP/TLS)
- `bind9-dnsutils` (para `dig`)

## 5. 🏗️ Instalación
El instalador gestiona las dependencias y la configuración automáticamente.

```bash
# 1. Clonar Repositorio
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit

# 2. Ejecutar Instalador (Interactivo)
sudo bash redaudit_install.sh

# 3. Recargar Shell (para activar el alias)
source ~/.bashrc  # o ~/.zshrc
```
*Nota: Usa `sudo bash redaudit_install.sh -y` para instalación no interactiva.*

## 6. 🚀 Inicio Rápido

### Modo Interactivo
Lanza la herramienta desde cualquier terminal:
```bash
redaudit
```
El asistente te guiará:
1.  **Selección de Objetivo**: Elige una subred local o introduce un CIDR manual (ej: `10.0.0.0/24`)
2.  **Modo de Escaneo**: Selecciona RÁPIDO, NORMAL o COMPLETO
3.  **Opciones**: Configura hilos, límite de velocidad y cifrado
4.  **Autorización**: Confirma que tienes permiso para escanear

### Modo No Interactivo (NUEVO en v2.5)
Para automatización y scripting:
```bash
# Escaneo básico
sudo redaudit --target 192.168.1.0/24 --mode normal

# Escaneo completo con cifrado
sudo redaudit --target 10.0.0.0/24 --mode full --threads 8 --encrypt --output /tmp/reports

# Múltiples objetivos
sudo redaudit --target "192.168.1.0/24,10.0.0.0/24" --mode normal --threads 6

    # Saltar advertencia legal (para automatización)
    sudo redaudit --target 192.168.1.0/24 --mode fast --yes

    # Con cifrado (contraseña aleatoria generada)
    sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --yes

    # Con cifrado (contraseña personalizada)
    sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --encrypt-password "MiContraseñaSegura123" --yes
```

**Opciones CLI Disponibles:**
- `--target, -t`: Red(es) objetivo en notación CIDR (requerido para modo no interactivo)
- `--mode, -m`: Modo de escaneo (fast/normal/full, por defecto: normal)
- `--threads, -j`: Hilos concurrentes (1-16, por defecto: 6)
- `--rate-limit`: Retardo entre hosts en segundos (por defecto: 0)
- `--encrypt, -e`: Cifrar reportes con contraseña
- `--output, -o`: Directorio de salida (por defecto: ~/RedAuditReports)
- `--max-hosts`: Máximo de hosts a escanear (por defecto: todos)
- `--no-vuln-scan`: Desactivar escaneo de vulnerabilidades web
- `--no-txt-report`: Desactivar generación de reporte TXT
- `--no-deep-scan`: Desactivar deep scan adaptativo
- `--yes, -y`: Saltar advertencia legal (usar con precaución)
- `--lang`: Idioma (en/es)

Ver `redaudit --help` para detalles completos.

## 7. ⚙️ Configuración y Parámetros Internos

### Concurrencia (Hilos)
RedAudit usa `ThreadPoolExecutor` de Python para escanear múltiples hosts simultáneamente.
- **Parámetro**: `threads` (Defecto: 6).
- **Rango**: 1–16.
- **Comportamiento**: Son *hilos* (threads), no procesos independientes. Comparten memoria pero ejecutan instancias de Nmap por separado.
    - **Alto (10-16)**: Escaneo más rápido, pero mayor carga de CPU y ruido en la red. Riesgo de congestión.
    - **Bajo (1-4)**: Más lento, más sigiloso y amable con redes antiguas o saturadas.

### Rate Limiting (Sigilo)
Controlado por el parámetro `rate_limit_delay`.
- **Mecanismo**: Introduce un `time.sleep(N)` *antes* de iniciar la tarea de escaneo de cada host.
- **Ajustes**:
    - **0s**: Velocidad máxima. Ideal para laboratorios o CTFs.
    - **1-5s**: Equilibrado. Recomendado para auditorías internas para evitar disparar limitadores simples.
    - **>5s**: Paranoico/Conservador. Úsalo en entornos de producción sensibles.

### Deep Scan Adaptativo (v2.5)
RedAudit aplica un escaneo inteligente de 2 fases a hosts "silenciosos" o complejos:
1.  **Fase 1**: TCP Agresivo (`-A -p- -sV -Pn`).
2.  **Fase 2**: Si la Fase 1 no revela MAC/SO, lanza detección de SO+UDP (`-O -sSU`).
- **Activación**: Automática.
- **Beneficio**: Ahorra tiempo saltando la Fase 2 si el host ya está identificado.
- **Salida**: Logs completos y datos MAC/Vendor en `host.deep_scan`.

## 8. 🔐 Reportes, Cifrado y Descifrado
Los reportes se guardan en `~/RedAuditReports` (por defecto) con fecha y hora.

### Cifrado (`.enc`)
Si activas **"¿Cifrar reportes?"** durante la configuración:
1.  Se genera un salt aleatorio de 16 bytes.
2.  Tu contraseña deriva una clave de 32 bytes vía **PBKDF2HMAC-SHA256** (480,000 iteraciones).
3.  Los archivos se cifran usando **Fernet (AES-128-CBC)**.
    - `report.json` → `report.json.enc`
    - `report.txt` → `report.txt.enc`
    - Se guarda un archivo `.salt` junto a ellos.

### Descifrado
Para leer tus reportes, **debes** tener el archivo `.salt` y recordar tu contraseña.
```bash
python3 redaudit_decrypt.py /ruta/a/report_NOMBRE.json.enc
```
*El script localiza automáticamente el archivo `.salt` correspondiente.*

## 9. 💓 Logging y Monitor de Actividad (Heartbeat)

### Logs de Aplicación
Logs de depuración y auditoría se guardan en `~/.redaudit/logs/`.
- **Rotación**: Mantiene los últimos 5 archivos, máx 10MB cada uno.
- **Contenido**: Rastrea PID de usuario, argumentos de comandos y excepciones.

### Monitor de Actividad (Heartbeat)
Un hilo en segundo plano (`threading.Thread`) monitoriza el estado del escaneo cada 30 segundos.
- **<60s silencio**: Normal (sin salida).
- **60-300s silencio**: Registra un **WARNING** indicando que Nmap puede estar ocupado.
- **>300s silencio**: Registra un **WARNING** con el mensaje "Nmap sigue ejecutándose; esto es normal en hosts lentos o filtrados."
- **Propósito**: Asegurar al operador que la herramienta sigue viva durante operaciones largas de Nmap (ej: escaneos `-p-`).

## 10. ✅ Script de Verificación
Verifica la integridad de tu entorno (checksums, dependencias, alias) en cualquier momento:
```bash
bash redaudit_verify.sh
```
*Útil tras actualizaciones del sistema o `git pull`.*

## 11. 📚 Glosario
- **Fernet**: Estándar de cifrado simétrico usando AES-128 y HMAC-SHA256.
- **Heartbeat**: Tarea en segundo plano que asegura que el proceso principal responde.
- **Deep Scan**: Escaneo de respaldo automático (`-A`) disparado cuando un host devuelve datos limitados.
- **PBKDF2**: Función de derivación de claves que encarece los ataques de fuerza bruta (configurada a 480k iteraciones).
- **Salt**: Dato aleatorio añadido al hash de contraseña para evitar ataques de rainbow table, guardado en archivos `.salt`.
- **Thread Pool**: Colección de hilos trabajadores que ejecutan tareas (escaneos de host) concurrentemente.

## 12. 🛠️ Solución de Problemas
Consulta [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) para soluciones detalladas.
- **"Permission denied"**: Asegúrate de usar `sudo`.
- **"Cryptography missing"**: Ejecuta `sudo apt install python3-cryptography`.
- **"Scan frozen"**: Revisa `~/.redaudit/logs/` o reduce `rate_limit_delay`.

## 13. ⚖️ Aviso Legal
**RedAudit** es una herramienta de seguridad únicamente para **auditorías autorizadas**.
Escanear redes sin permiso es ilegal. Al usar esta herramienta, aceptas total responsabilidad por tus acciones y acuerdas usarla solo en sistemas de tu propiedad o para los que tengas autorización explícita.

## 14. 📝 Historial de Cambios (Resumen v2.5)
- **Seguridad**: Sanitización de entrada endurecida con validación de tipo/longitud, permisos de archivo seguros (0o600)
- **Automatización**: Modo CLI completo no interactivo para scripting e integración CI/CD
- **Testing**: Suites de tests completas de integración y cifrado
- **Robustez**: Manejo mejorado de cryptography con degradación graceful
- **Documentación**: Actualizaciones completas de documentación en inglés y español

Para el changelog detallado, consulta [CHANGELOG.md](CHANGELOG.md)

## 15. ⚖️ Licencia

RedAudit se distribuye bajo la **GNU General Public License v3.0 (GPLv3)**.  
Consulta el archivo [LICENSE](LICENSE) para ver el texto completo y las condiciones.

## 16. 🧠 Internos & Glosario (Por qué RedAudit se comporta así)

### Pool de hilos (`threads`)
RedAudit utiliza un *pool* de hilos para escanear varios hosts en paralelo.  
El parámetro `threads` controla cuántos hosts se analizan simultáneamente:
- Valor bajo (2–4): más lento, pero más sigiloso y con menos ruido.
- Valor medio (por defecto, 6): buen equilibrio para la mayoría de entornos.
- Valor alto (10–16): más rápido, pero puede generar más ruido y más timeouts.

### Limitación de tasa (*rate limiting*)
Para no saturar la red, RedAudit puede introducir un pequeño retardo entre host y host.  
Esto sacrifica velocidad a cambio de estabilidad y menor huella en entornos sensibles.

### Heartbeat y watchdog
En escaneos largos, RedAudit muestra mensajes de *heartbeat* cuando lleva un tiempo sin imprimir nada.  
Sirve para distinguir un escaneo “silencioso pero sano” de un bloqueo real.

### Reportes cifrados
Los reportes pueden cifrarse con contraseña.  
La clave se deriva con PBKDF2-HMAC-SHA256 (480k iteraciones) y se acompaña de un archivo `.salt` para poder descifrarlos posteriormente con `redaudit_decrypt.py`.

---
[Documentación Completa](docs/) | [Esquema de Reporte](docs/REPORT_SCHEMA.md) | [Especificaciones de Seguridad](docs/SECURITY.md)
