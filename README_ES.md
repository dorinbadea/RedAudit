<div align="center">
  <img src="assets/header.png" alt="RedAudit Banner" width="100%">

  <br>

  [ 🇬🇧 English ](README.md) | [ 🇪🇸 Español ](README_ES.md)

  <br>

  ![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)
  ![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
  ![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
</div>

<br>

**RedAudit** es una herramienta de auditoría de red interactiva y automatizada diseñada para Kali Linux. Agiliza el proceso de reconocimiento combinando descubrimiento de red, escaneo de puertos y evaluación de vulnerabilidades en un flujo de trabajo CLI único y fácil de usar.

## 🖥️ Preview

```text
    ____          _    _   _           _ _ _
   / __ \___  ___| |  / \  _   _  __| (_) |_
  / /_/ / _ \/ __| | / _ \| | | |/ _` | | __|
 / _, _/  __/ (__| |/ ___ \ |_| | (_| | | |_
/_/ |_|\___|\___|_|/_/   \_\__,_|\__,_|_|\__|
                                      v2.3
══════════════════════════════════════════════════════
   AUDITORÍA DE RED INTERACTIVA  ::  KALI LINUX
══════════════════════════════════════════════════════

? CONFIGURACIÓN DE ESCANEO
============================================================

? SELECCIÓN DE OBJETIVO
--------------------------------------------------
✓ Interfaces detectadas:
   1. 192.168.1.0/24 (eth0) - ~253 hosts
   2. Introducir manual
   3. Escanear TODAS

? Selecciona red: [1-3] (1): 
```

## Características

- **CLI interactiva** con menús guiados para seleccionar objetivos, modo de escaneo y opciones.
- **Detección automática de redes locales** (`ip` / `netifaces`) para sugerir rangos CIDR razonables.
- **Escaneo en varios modos**:
  - **RÁPIDO** – solo descubrimiento de hosts (`-sn`), ruido mínimo.
  - **NORMAL** – puertos principales + detección de servicio/versión (equilibrio entre velocidad y cobertura).
  - **COMPLETO** – todos los puertos, scripts, detección de SO y servicios, más comprobaciones web opcionales.
- **Deep Scans automáticos** para hosts “silenciosos” o con errores (pasadas extra de Nmap, sondeo UDP y captura opcional con `tcpdump`).
- **Reconocimiento web** con `whatweb` y `nikto` cuando están disponibles, más enriquecimiento opcional con `curl` / `wget` / `openssl`.
- **Enriquecimiento de tráfico y DNS**: pequeñas capturas PCAP (`tcpdump` + `tshark`) y resolución inversa / whois para IPs públicas.
- **Endurecimiento y Seguridad**: Validación estricta de entradas y fallback a deep scan.
- **Cifrado de Reportes**: Cifrado opcional AES-128 (Fernet) para reportes (JSON/TXT). Incluye herramienta `redaudit_decrypt.py`.
- **Rate Limiting**: Retardo configurable entre hosts para mayor sigilo.
- **Logging Profundo**: Logs rotativos en `~/.redaudit/logs/` para auditoría y depuración.
- **Resiliencia**: Monitor de actividad (heartbeat) y salida elegante con Ctrl+C.
- **Núcleo Embebido**: Instalador único (`redaudit_install.sh`) gestiona dependencias y el código Python.

Consulta la [Guía de Uso](docs/USAGE_ES.md) y [Solución de Problemas](docs/TROUBLESHOOTING.md) (en inglés) para más detalles.

## Dependencias

RedAudit está pensado para **sistemas basados en Debian con `apt`** (Kali, Debian, Ubuntu…).

### Requeridas (núcleo)

Imprescindibles para que la herramienta funcione:

- `nmap`
- `python3-nmap`
- `python3-cryptography` (para cifrado de reportes)

### Recomendadas (enriquecimiento)

Opcionales pero muy recomendables si quieres sacar todo el partido a las funciones web / tráfico / DNS:

- `whatweb`
- `nikto`
- `curl`, `wget`, `openssl`
- `tcpdump`, `tshark`
- `whois`, `bind9-dnsutils` (para `dig`)

Instalación rápida de todo en Kali/Debian/Ubuntu:

```bash
sudo apt update
sudo apt install nmap python3-nmap python3-cryptography whatweb nikto \
  curl wget openssl tcpdump tshark whois bind9-dnsutils
```

El instalador y el núcleo en Python comprueban estas dependencias en tiempo de ejecución y ajustan el comportamiento (menos funciones si falta algo). Aunque el instalador puede ayudarte a instalar ciertos paquetes vía apt, la forma recomendada y documentada es gestionarlos tú mismo con los comandos anteriores.

## Arquitectura y flujo

A alto nivel, una ejecución sigue este flujo:

1.	**Inicialización**
	-	Detecta interfaces y redes locales.
	-	Te pide seleccionar uno o varios rangos objetivo.
	-	Permite elegir modo de escaneo (RÁPIDO / NORMAL / COMPLETO) y número de hilos.
	-	Opcionalmente activa el análisis web y permite elegir el directorio de salida.
2.	**Fase de descubrimiento**
	-	Ejecuta un discovery rápido de Nmap (-sn) sobre cada rango seleccionado.
	-	Construye una lista de hosts que responden; esa lista se usa después para los escaneos profundos.
3.	**Escaneo por host**
	-	Itera sobre los hosts vivos usando un thread pool.
	-	Para cada host, ejecuta los flags de Nmap correspondientes al modo elegido.
	-	Registra puertos abiertos, nombres de servicio, versiones y si tienen pinta de servicio web.
4.	**Lógica de Deep Scan**
	-	Si un host devuelve muy pocos puertos o errores sospechosos, lanza un Deep Scan específico:
	-	Escaneo agresivo de Nmap (-A -sV -Pn -p- --open) y sondeo UDP opcional.
	-	Captura corta de tráfico alrededor del host con tcpdump (más un resumen vía tshark si está disponible).
5.	**Enriquecimiento**
	-	Para puertos que parecen web (HTTP/HTTPS, proxies, paneles de admin, etc.), opcionalmente:
		-	Ejecuta whatweb para un fingerprint rápido.
		-	Lanza nikto en modo COMPLETO para detectar patrones de mala configuración o vulnerabilidades típicas.
		-	Extrae cabeceras HTTP y detalles TLS con curl, wget y openssl.
	-	Para IPs públicas, opcionalmente:
		-	Realiza resolución inversa con dig.
		-	Añade un resumen recortado de whois.
6.	**Reportes**
	-	Agrega toda la información en una estructura JSON única y en un informe de texto.
	-	Escribe los ficheros en `~/RedAuditReports` por defecto, o en el directorio elegido durante la configuración.
	-	Si se interrumpe la ejecución (Ctrl+C), se guarda igualmente un informe parcial para no perder el trabajo previo.

## Características de Seguridad
RedAudit está diseñado para entornos hostiles y aplica seguridad estricta:
- **Sanitización de Entrada**: Todas las IPs y hostnames se validan contra regex estricta (`^[a-zA-Z0-9\.\-]+$`) y la librería `ipaddress`.
- **Cifrado de Reportes**: Usa **AES-128 (Fernet)** con claves derivadas vía **PBKDF2HMAC-SHA256** (480,000 iteraciones).
- **Monitor de Actividad**: Un hilo "heartbeat" detecta bloqueos de Nmap (>300s) y asegura que la herramienta no se cuelgue en silencio.

## Verificación
Para verificar la integridad de tu instalación y dependencias, ejecuta el script incluido:
```bash
bash redaudit_verify.sh
```
Esto comprueba el binario, el alias, las librerías Python (`cryptography`) y herramientas opcionales (`tcpdump`, `whatweb`, etc).

## Descifrando Reportes
Si activaste el cifrado, tendrás archivos `.json.enc` y `.salt`. Para descifrar:

```bash
python3 redaudit_decrypt.py /ruta/a/reporte_TIMESTAMP.json.enc
```
**Nota**: El archivo `.salt` debe estar en el mismo directorio. Se te pedirá la contraseña usada durante el escaneo.

## Desinstalación

1.	Clona el repositorio:

    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.	Da permisos de ejecución al instalador y ejecútalo como root (o con sudo):

    ```bash
    chmod +x redaudit_install.sh

    # Modo interactivo (pregunta si quieres instalar herramientas recomendadas cuando corresponda)
    sudo bash redaudit_install.sh

    # Modo no interactivo: asume “sí” a la pregunta de herramientas opcionales
    sudo bash redaudit_install.sh -y
    ```

3.	Recarga la configuración de tu shell para habilitar el alias redaudit:

    ```bash
    source ~/.bashrc    # o ~/.zshrc
    ```

## Uso

Tras la instalación, puedes lanzar RedAudit desde cualquier terminal:

```bash
redaudit
```

El asistente interactivo te guía por:
1.	**Selección de objetivo**: elegir una de las redes locales detectadas o introducir un CIDR manualmente.
2.	**Modo de escaneo**: RÁPIDO, NORMAL o COMPLETO.
3.	**Opciones**: número de hilos, si incluir análisis de vulnerabilidades web y dónde guardar los reportes.
4.	**Autorización**: confirmación explícita de que tienes permiso para escanear los objetivos seleccionados.
5.  **Cifrado**: Opción para cifrar los reportes de salida con contraseña.

Los informes se guardarán por defecto en `~/RedAuditReports`. Si se activa el cifrado, los archivos tendrán extensión `.json.enc` y `.txt.enc` junto a un archivo `.salt`.

### Descifrado de Reportes

Si elegiste cifrar tus reportes, usa el script de ayuda proporcionado:

```bash
python3 redaudit_decrypt.py ~/RedAuditReports/redaudit_...json.enc
```

Se te pedirá la contraseña usada durante la auditoría.

## ⚠️ Aviso legal y ético

RedAudit es una herramienta de seguridad destinada únicamente a auditorías autorizadas y fines educativos. Escanear sistemas o redes sin permiso explícito es ilegal y puede ser sancionado por la ley, tanto a nivel penal como civil.

Al usar esta herramienta aceptas que:
-	Solo la ejecutarás sobre activos que sean tuyos o para los que tengas permiso documentado.
-	No la utilizarás con fines maliciosos, intrusivos o disruptivos.
-	Tú, como operador, eres el único responsable de cumplir la normativa y las políticas aplicables.

Los autores declinan cualquier responsabilidad derivada del uso indebido de este software.

## Licencia

Este proyecto se distribuye bajo licencia MIT. Consulta el archivo LICENSE para más detalles.
