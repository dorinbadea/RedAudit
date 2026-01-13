# RedAudit Vulnerable Lab Setup

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](LAB_SETUP_ES.md)

This guide explains how to set up the **RedAudit Testing Lab** using Docker. This environment mimics a real-world network with various vulnerable machines, SCADA systems, Active Directory, and IoT devices.

The lab corresponds to the credentials provided in `scripts/seed_keyring.py`.

## Prerequisites

### 1. The Lab (Victim Environment)

- **Host OS**: Linux (Ubuntu/Debian recommended), macOS, or Windows (with Docker Desktop)
- **Docker**: Must be installed and running (`sudo systemctl start docker`)
- **Python 3**: For running the credential seeder

### 2. The Auditor (RedAudit)

RedAudit is designed to run on a **dedicated physical machine** or **Virtual Machine** (VMware/VirtualBox) running Linux (Kali/Debian/Ubuntu).

- **Native/VM (Recommended)**: Use the `redaudit_install.sh` script on a Linux system/VM (with bridged networking) for full L2 visibility.
- **Docker (Optional)**: RedAudit has a [Dockerized version](DOCKER.md), but on Windows/macOS/Docker it is limited to the local network bridge (no external ARP/L2 visibility). See [DOCKER.md](DOCKER.md).

## Real-World Validation Note

> **Note**: This Docker lab is provided for **reproducibility** so users can safely test RedAudit's features.
>
> RedAudit is primarily developed and battle-tested in a **complex physical environment** featuring enterprise-grade routers, switches, hardware firewalls, physical IoT devices, and diverse operating systems. This Docker setup is a lightweight simulation of that environment designed for community use.

## Quick Start (Automated)

We provide a helper script to manage the entire lifecycle of the lab.

```bash
# 1. Install and provision the lab
sudo bash scripts/setup_lab.sh install

# 2. Check status (IPs and uptime)
sudo bash scripts/setup_lab.sh status
```

## Lab Management

| Action | Command | Description |
| :--- | :--- | :--- |
| **Start** | `sudo bash scripts/setup_lab.sh start` | Starts all stopped containers |
| **Stop** | `sudo bash scripts/setup_lab.sh stop` | Stops all running containers (frees resources) |
| **Remove** | `sudo bash scripts/setup_lab.sh remove` | DELETEs all containers and the network |
| **Status** | `sudo bash scripts/setup_lab.sh status` | Lists containers and pings IPs |

## Docker Service Management

```bash
# Enable and start Docker (persistent)
sudo systemctl enable --now docker

# Disable and stop Docker (free resources)
sudo systemctl disable --now docker.socket && sudo systemctl stop docker
```

## Orchestration Commands

```bash
# Start all lab containers
docker start $(docker ps -aq --filter "network=lab_seguridad")

# Stop all lab containers
docker stop $(docker ps -q --filter "network=lab_seguridad")

# Health check (ping all)
for i in 10 11 12 13 14 15 20 30 40 50 51 60 70 71; do
  ping -c1 -W1 172.20.0.$i &>/dev/null && echo "172.20.0.$i [UP]" || echo "172.20.0.$i [DOWN]"
done
```

## Network Layout

- **Network**: `lab_seguridad`
- **Subnet**: `172.20.0.0/24`
- **Gateway**: `172.20.0.1`

### Targets

| IP | Hostname | Role | User | Password | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **.10** | `juiceshop` | Web (Node.js) | `admin@juice-sh.op` | `pwned` | OWASP Top 10 |
| **.11** | `metasploitable` | Linux Legacy | `msfadmin` | `msfadmin` | SSH/SMB/Telnet |
| **.12** | `dvwa` | Web (PHP) | `admin` | `password` | SQLi, XSS |
| **.13** | `webgoat` | Web (Java) | `guest` | `guest` | Training |
| **.14** | `hackazon` | E-commerce | `admin` | `admin` | SQLi, XSS |
| **.15** | `bwapp` | Web | `bee` | `bug` | Buggy App |
| **.20** | `target-ssh-lynis` | Ubuntu Hardened | `auditor` | `redaudit` | SSH Compliance |
| **.30** | `target-windows` | SMB Server | `docker` | `password123` | Port 445 |
| **.40** | `target-snmp` | SNMP v3 | `admin-snmp` | `auth_pass_123` | SHA/AES |
| **.50** | `openplc-scada` | SCADA | `openplc` | `openplc` | Modbus TCP |
| **.51** | `conpot-ics` | ICS Honeypot | *(anon)* | *(anon)* | S7/Modbus |
| **.60** | `samba-ad` | Active Directory DC | `Administrator` | `P@ssw0rd123` | `REDAUDITAD.LABORATORIO.LAN` |
| **.70** | `iot-camera` | IoT Camera | `admin` | `admin` | GoAhead RCE |
| **.71** | `iot-router` | IoT Router | `admin` | `password` | Web/IoT |

## Installation Commands (Verified)

### Core Group (Web and Legacy)

```bash
docker run -d --name juiceshop --net lab_seguridad --ip 172.20.0.10 bkimminich/juice-shop
docker run -d --name metasploitable --net lab_seguridad --ip 172.20.0.11 -t tleemcjr/metasploitable2
docker run -d --name dvwa --net lab_seguridad --ip 172.20.0.12 vulnerables/web-dvwa
docker run -d --name webgoat --net lab_seguridad --ip 172.20.0.13 webgoat/webgoat
docker run -d --name hackazon --net lab_seguridad --ip 172.20.0.14 ianwijaya/hackazon
docker run -d --name bwapp --net lab_seguridad --ip 172.20.0.15 raesene/bwapp
```

### Phase 4 Group (SSH, SMB, SNMP, AD, SCADA)

```bash
# .20 SSH with password authentication (linuxserver/openssh-server)
docker run -d --name target-ssh-lynis --net lab_seguridad --ip 172.20.0.20 \
  -e PUID=1000 -e PGID=1000 \
  -e USER_NAME=auditor -e USER_PASSWORD=redaudit \
  -e PASSWORD_ACCESS=true \
  linuxserver/openssh-server

# .30 SMB Server (elswork/samba - requires volume + runtime args)
sudo mkdir -p /srv/lab_smb/Public
sudo chown -R "$(id -u):$(id -g)" /srv/lab_smb
docker run -d --name target-windows --net lab_seguridad --ip 172.20.0.30 \
  -v /srv/lab_smb/Public:/share/public \
  elswork/samba \
  -u "$(id -u):$(id -g):docker:docker:password123" \
  -s "Public:/share/public:rw:docker"

# .40 SNMP v3
docker run -d --name target-snmp --net lab_seguridad --ip 172.20.0.40 polinux/snmpd

# .50-.51 Industrial and Honeypot
docker run -d --name openplc-scada --net lab_seguridad --ip 172.20.0.50 \
  -p 8443:8443 ghcr.io/autonomy-logic/openplc-runtime:latest
docker run -d --name conpot-ics --net lab_seguridad --ip 172.20.0.51 honeynet/conpot:latest

# .60 Samba AD DC (requires volumes and correct env vars)
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

> **Note**: The Samba AD controller (`.60`) takes 3-5 minutes on first boot to provision the directory.

## Scanning with RedAudit

Once the lab is running (`status` shows UP):

1. **Seed Credentials** (optional, one-time):

   ```bash
   python3 scripts/seed_keyring.py
   ```

2. **Sync SSH Password** (if needed):

   ```bash
   keyring set redaudit ssh_auditor
   # Enter: redaudit
   ```

3. **Run Scan**:

   ```bash
   sudo redaudit -t 172.20.0.0/24
   ```

4. **Wizard**: The wizard will detect the network, offer to load saved credentials, and then ask if you want to add more.

## Troubleshooting

### Target Windows (.30) Not Starting / Samba Error

If the SMB server at `172.20.0.30` fails to start cleanly or is unreachable, use this manual refresh command to force a clean deployment:

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
