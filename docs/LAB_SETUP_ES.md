# Configuración del Laboratorio RedAudit

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](LAB_SETUP.md)

Esta guía explica cómo configurar el **Laboratorio de Pruebas RedAudit** usando Docker. Este entorno imita una red real con varias máquinas vulnerables, sistemas SCADA, Active Directory y dispositivos IoT.

El laboratorio corresponde a las credenciales proporcionadas en `scripts/seed_keyring.py`.

## Requisitos Previos

### 1. El Laboratorio (Entorno Víctima)

- **SO Host**: Linux (Ubuntu/Debian recomendado), macOS o Windows (con Docker Desktop)
- **Docker**: Debe estar instalado y ejecutándose (`sudo systemctl start docker`)
- **Python 3**: Para ejecutar el seeder de credenciales

### 2. El Auditor (RedAudit)

RedAudit está diseñado para ejecutarse en una **máquina física dedicada** o **Máquina Virtual** (VMware/VirtualBox) con Linux (Kali/Debian/Ubuntu).

- **Nativo/VM (Recomendado)**: Usa el script `redaudit_install.sh` en un sistema Linux/VM (con red en modo puente/bridge) para visibilidad L2 completa.
- **Docker (Opcional)**: RedAudit tiene una [versión Dockerizada](DOCKER.es.md), pero en Windows/macOS/Docker se limita a la red local "bridge" (sin visibilidad L2/ARP externa). Ver [DOCKER.es.md](DOCKER.es.md).

## Nota sobre Validacion en Mundo Real

> **Nota**: Este laboratorio Docker se proporciona para la **reproducibilidad**, permitiendo a los usuarios probar RedAudit de forma segura.
>
> RedAudit se desarrolla y valida principalmente en un **entorno fisico complejo** que incluye routers empresariales, switches, firewalls de hardware, dispositivos IoT fisicos y diversos sistemas operativos. Este setup Docker es una simulacion ligera de ese entorno, diseñada para el uso de la comunidad.

## Inicio Rápido (Automatizado)

Proporcionamos un script de ayuda para gestionar todo el ciclo de vida del laboratorio.

```bash
# 1. Instalar y aprovisionar el laboratorio
sudo bash scripts/setup_lab.sh install

# 2. Comprobar estado (IPs y uptime)
sudo bash scripts/setup_lab.sh status
```

## Gestión del Laboratorio

| Acción | Comando | Descripción |
| :--- | :--- | :--- |
| **Iniciar** | `sudo bash scripts/setup_lab.sh start` | Inicia todos los contenedores detenidos |
| **Parar** | `sudo bash scripts/setup_lab.sh stop` | Detiene todos los contenedores (libera recursos) |
| **Eliminar** | `sudo bash scripts/setup_lab.sh remove` | BORRA todos los contenedores y la red |
| **Estado** | `sudo bash scripts/setup_lab.sh status` | Lista contenedores y hace ping a IPs |

## Estructura de Red

- **Red**: `lab_seguridad`
- **Subred**: `172.20.0.0/24`
- **Gateway**: `172.20.0.1`

### Objetivos

| IP | hostname | Rol | Vulnerabilidades Clave |
| :--- | :--- | :--- | :--- |
| **.10** | `juiceshop` | Web (Node.js) | OWASP Top 10 |
| **.11** | `metasploitable` | Linux Legacy | Credenciales débiles SSH/SMB/Telnet |
| **.12** | `dvwa` | Web (PHP) | SQLi, XSS, Inyección de Comandos |
| **.13** | `webgoat` | Web (Java) | Vulnerabilidades de entrenamiento |
| **.15** | `bwapp` | Web | Aplicación Web con Bugs |
| **.20** | `target-ssh-lynis` | Ubuntu Hardened | Pruebas de Cumplimiento SSH |
| **.30** | `target-windows` | Simulación Windows | SMB NULL Session |
| **.40** | `target-snmp` | SNMP v3 | Configuración Auth/Priv débil |
| **.50** | `openplc-scada` | SCADA | Modbus TCP (502) |
| **.51** | `conpot-ics` | ICS Honeypot | Siemens S7, Modbus |
| **.60** | `samba-ad` | Active Directory | LDAP, SMB, Kerberos (`REDAUDIT.LOCAL`) |
| **.70** | `iot-camera` | Cámara IoT | Credenciales por defecto |
| **.71** | `iot-router` | Router IoT | Administración web débil |

## Escaneando con RedAudit

Una vez que el laboratorio esté funcionando (`status` muestra UP):

1. **Cargar Credenciales** (opcional, una vez):

   ```bash
   python3 scripts/seed_keyring.py
   ```

2. **Ejecutar Escaneo**:

   ```bash
   sudo redaudit -t 172.20.0.0/24
   ```

3. **Asistente**: Detectará la red y ofrecerá cargar las credenciales guardadas.
