# Configuracion del Laboratorio RedAudit

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](LAB_SETUP.md)

Esta guia explica como configurar el **Laboratorio de Pruebas RedAudit** usando Docker. Este entorno imita una red real con varias maquinas vulnerables, sistemas SCADA, Active Directory y dispositivos IoT.

El laboratorio corresponde a las credenciales proporcionadas en `scripts/seed_keyring.py`.

## Requisitos Previos

### 1. El Laboratorio (Entorno Victima)

- **SO Host**: Linux (Ubuntu/Debian recomendado), macOS o Windows (con Docker Desktop)
- **Docker**: Debe estar instalado y ejecutandose (`sudo systemctl start docker`)
- **Python 3**: Para ejecutar el seeder de credenciales

### 2. El Auditor (RedAudit)

RedAudit esta diseñado para ejecutarse en una **maquina fisica dedicada** o **Maquina Virtual** (VMware/VirtualBox) con Linux (Kali/Debian/Ubuntu).

- **Nativo/VM (Recomendado)**: Usa el script `redaudit_install.sh` en un sistema Linux/VM (con red en modo puente/bridge) para visibilidad L2 completa.
- **Docker (Opcional)**: RedAudit tiene una [version Dockerizada](DOCKER.es.md), pero en Windows/macOS/Docker se limita a la red local "bridge" (sin visibilidad L2/ARP externa). Ver [DOCKER.es.md](DOCKER.es.md).

## Nota sobre Validacion en Mundo Real

> **Nota**: Este laboratorio Docker se proporciona para la **reproducibilidad**, permitiendo a los usuarios probar RedAudit de forma segura.
>
> RedAudit se desarrolla y valida principalmente en un **entorno fisico complejo** que incluye routers empresariales, switches, firewalls de hardware, dispositivos IoT fisicos y diversos sistemas operativos. Este setup Docker es una simulacion ligera de ese entorno, diseñada para el uso de la comunidad.

## Inicio Rapido (Automatizado)

Proporcionamos un script de ayuda para gestionar todo el ciclo de vida del laboratorio.

```bash
# 1. Instalar y aprovisionar el laboratorio
sudo bash scripts/setup_lab.sh install

# 2. Comprobar estado (IPs y uptime)
sudo bash scripts/setup_lab.sh status
```

**Rotación de logs**: El script configura rotación de logs de Docker para evitar crecimiento excesivo de `*-json.log`. Si creaste el lab antes de este cambio, recrea los contenedores para aplicarlo.

## Gestion del Laboratorio

| Accion | Comando | Descripcion |
| :--- | :--- | :--- |
| **Iniciar** | `sudo bash scripts/setup_lab.sh start` | Inicia todos los contenedores detenidos |
| **Parar** | `sudo bash scripts/setup_lab.sh stop` | Detiene todos los contenedores (libera recursos) |
| **Eliminar** | `sudo bash scripts/setup_lab.sh remove` | BORRA todos los contenedores y la red |
| **Estado** | `sudo bash scripts/setup_lab.sh status` | Lista contenedores y hace ping a IPs |

## Limpieza del laboratorio (cuando ya no lo necesitas)

Usa esto cuando quieras eliminar completamente el laboratorio del sistema.

```bash
# Elimina contenedores del lab, red y volumenes con nombre
sudo bash scripts/setup_lab.sh remove

# Opcional: elimina solo las imagenes del laboratorio (seguro si no las usas en otros entornos)
docker image rm \
  bkimminich/juice-shop \
  tleemcjr/metasploitable2 \
  vulnerables/web-dvwa \
  webgoat/webgoat \
  ianwijaya/hackazon \
  raesene/bwapp \
  linuxserver/openssh-server \
  elswork/samba \
  polinux/snmpd \
  ghcr.io/autonomy-logic/openplc-runtime:latest \
  honeynet/conpot:latest \
  nowsci/samba-domain \
  vulhub/goahead:3.6.4

# Opcional: elimina volumenes sin uso tras borrar el lab
docker volume prune
```

## Gestion del Servicio Docker

```bash
# Habilitar e iniciar Docker (persistente)
sudo systemctl enable --now docker

# Deshabilitar y detener Docker (liberar recursos)
sudo systemctl disable --now docker.socket && sudo systemctl stop docker
```

## Comandos de Orquestacion

```bash
# Arrancar todos los contenedores del lab
docker start $(docker ps -aq --filter "network=lab_seguridad")

# Parar todos los contenedores del lab
docker stop $(docker ps -q --filter "network=lab_seguridad")

# Check de salud (ping a todos)
for i in 10 11 12 13 14 15 20 30 40 50 51 60 70 71; do
  ping -c1 -W1 172.20.0.$i &>/dev/null && echo "172.20.0.$i [UP]" || echo "172.20.0.$i [DOWN]"
done
```

## Estructura de Red

- **Red**: `lab_seguridad`
- **Subred**: `172.20.0.0/24`
- **Gateway**: `172.20.0.1`

### Objetivos

| IP | Hostname | Rol | Usuario | Contrasena | Notas |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **.10** | `juiceshop` | Web (Node.js) | `admin@juice-sh.op` | `pwned` | OWASP Top 10 |
| **.11** | `metasploitable` | Linux Legacy | `msfadmin` | `msfadmin` | SSH/SMB/Telnet |
| **.12** | `dvwa` | Web (PHP) | `admin` | `password` | SQLi, XSS |
| **.13** | `webgoat` | Web (Java) | `guest` | `guest` | Entrenamiento |
| **.14** | `hackazon` | E-commerce | `admin` | `admin` | SQLi, XSS |
| **.15** | `bwapp` | Web | `bee` | `bug` | App con Bugs |
| **.20** | `target-ssh-lynis` | Ubuntu Hardened | `auditor` | `redaudit` | SSH Compliance |
| **.30** | `target-windows` | Servidor SMB | `docker` | `password123` | Puerto 445 |
| **.40** | `target-snmp` | SNMP v3 | `admin-snmp` | `auth_pass_123` | SHA/AES |
| **.50** | `openplc-scada` | SCADA | `openplc` | `openplc` | Modbus TCP |
| **.51** | `conpot-ics` | ICS Honeypot | *(anon)* | *(anon)* | S7/Modbus |
| **.60** | `samba-ad` | Active Directory DC | `Administrator` | `P@ssw0rd123` | `REDAUDITAD.LABORATORIO.LAN` |
| **.70** | `iot-camera` | Camara IoT | `admin` | `admin` | GoAhead RCE |
| **.71** | `iot-router` | Router IoT | `admin` | `password` | Web/IoT |

## Comandos de Instalacion (Verificados)

El script automatizado aplica rotacion de logs de Docker a todos los contenedores. Si ejecutas estos comandos manualmente, anade:

```
--log-driver local --log-opt max-size=10m --log-opt max-file=3
```

### Grupo Core (Web y Legacy)

```bash
docker run -d --name juiceshop --net lab_seguridad --ip 172.20.0.10 bkimminich/juice-shop
docker run -d --name metasploitable --net lab_seguridad --ip 172.20.0.11 -t tleemcjr/metasploitable2
docker run -d --name dvwa --net lab_seguridad --ip 172.20.0.12 vulnerables/web-dvwa
docker run -d --name webgoat --net lab_seguridad --ip 172.20.0.13 webgoat/webgoat
docker run -d --name hackazon --net lab_seguridad --ip 172.20.0.14 ianwijaya/hackazon
docker run -d --name bwapp --net lab_seguridad --ip 172.20.0.15 raesene/bwapp
```

### Grupo Phase 4 (SSH, SMB, SNMP, AD, SCADA)

```bash
# .20 SSH con autenticacion por contrasena (linuxserver/openssh-server)
docker run -d --name target-ssh-lynis --net lab_seguridad --ip 172.20.0.20 \
  -e PUID=1000 -e PGID=1000 \
  -e USER_NAME=auditor -e USER_PASSWORD=redaudit \
  -e PASSWORD_ACCESS=true \
  linuxserver/openssh-server

# .30 Servidor SMB (elswork/samba - requiere volumen + args runtime)
docker rm -f target-windows 2>/dev/null

sudo mkdir -p /srv/lab_smb/Public
sudo chown -R "$(id -u):$(id -g)" /srv/lab_smb
docker run -d --name target-windows --net lab_seguridad --ip 172.20.0.30 \
  -v /srv/lab_smb/Public:/share/public \
  elswork/samba \
  -u "$(id -u):$(id -g):docker:docker:password123" \
  -s "Public:/share/public:rw:docker"

# .40 SNMP v3
docker run -d --name target-snmp --net lab_seguridad --ip 172.20.0.40 polinux/snmpd

# .50-.51 Industrial y Honeypot
docker run -d --name openplc-scada --net lab_seguridad --ip 172.20.0.50 \
  -p 8443:8443 ghcr.io/autonomy-logic/openplc-runtime:latest
docker run -d --name conpot-ics --net lab_seguridad --ip 172.20.0.51 honeynet/conpot:latest

# .60 Samba AD DC (requiere volumenes y env vars correctos)
docker volume create samba_ad_data
docker volume create samba_ad_cfg
docker run -d --name samba-ad --hostname dc1 --privileged \
  --net lab_seguridad --ip 172.20.0.60 \
  -e "DOMAIN=REDAUDITAD.LABORATORIO.LAN" \
  -e "DOMAINPASS=P@ssw0rd123" \
  -e "HOSTIP=172.20.0.60" \
  -e "DNSFORWARDER=8.8.8.8" \
  -v samba_ad_data:/var/lib/samba \
  -v samba_ad_cfg:/etc/samba/external \
  --dns 172.20.0.60 --dns 8.8.8.8 \
  --dns-search redauditad.laboratorio.lan \
  nowsci/samba-domain

# .70-.71 IoT
docker run -d --name iot-camera --net lab_seguridad --ip 172.20.0.70 vulhub/goahead:3.6.4
docker run -d --name iot-router --net lab_seguridad --ip 172.20.0.71 webgoat/webgoat
```

> **Nota**: El controlador de dominio Samba AD (`.60`) tarda 3-5 minutos en su primer arranque para aprovisionar el directorio.

## Escaneando con RedAudit

Una vez que el laboratorio este funcionando (`status` muestra UP):

1. **Cargar Credenciales** (opcional, una vez):

   ```bash
   python3 scripts/seed_keyring.py
   ```

2. **Sincronizar Contrasena SSH** (si es necesario):

   ```bash
   keyring set redaudit ssh_auditor
   # Introduce: redaudit
   ```

3. **Ejecutar Escaneo**:

   ```bash
   sudo redaudit -t 172.20.0.0/24
   ```

4. **Asistente**: El asistente detectara la red, ofrecera cargar credenciales guardadas y luego preguntara si deseas anadir mas.

## Solución de Problemas

### Target Windows (.30) No Inicia / Error Samba

Si el servidor SMB en `172.20.0.30` falla al iniciar o no es accesible, usa este comando manual para forzar un despliegue limpio:

```bash
docker rm -f target-windows 2>/dev/null

sudo mkdir -p /srv/lab_smb/Public
sudo chown -R "$(id -u)":"$(id -g)" /srv/lab_smb

docker run -d --name target-windows --net lab_seguridad --ip 172.20.0.30 \
  -v /srv/lab_smb/Public:/share/public \
  elswork/samba \
  -u "$(id -u):$(id -g):docker:docker:password123" \
  -s "Public:/share/public:rw:docker"
```

### RustScan y Redes Docker Bridge

> **Nota**: Al escanear el laboratorio Docker (172.20.0.0/24), los escáneres rápidos (RustScan) pueden no detectar puertos abiertos debido a limitaciones conocidas con las redes bridge de Docker.

**Que sucede**:

- Los escáneres rápidos usan sockets raw (libpcap) que no enrutan correctamente a traves del bridge virtual de Docker
- RedAudit usa automaticamente escaneo estándar como fallback cuando el descubrimiento rápido retorna 0 puertos
- Scapy funciona correctamente con redes Docker

**Comportamiento esperado**:

- Tiempo de escaneo: ~1 minuto por host Docker (en lugar de segundos con RustScan)
- Deteccion de puertos: Precisa (via fallback Scapy)
- No se requiere accion - el fallback es automatico

**Para escaneos de lab mas rapidos**, considera usar `--hyperscan-mode full` que usa el escaner TCP connect asyncio directamente.
