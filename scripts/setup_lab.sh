#!/bin/bash
# RedAudit Lab Setup Script
#
# Usage:
#   ./setup_lab.sh [install|start|stop|remove|status]
#
# This script sets up the "lab_seguridad" Docker environment used for testing RedAudit.
# Network: 172.20.0.0/24
#
# Updated: 2026-01-11 - Verified working commands from real deployment

LAB_NET="lab_seguridad"
LAB_SUBNET="172.20.0.0/24"
LAB_GATEWAY="172.20.0.1"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Docker log rotation (prevents giant json-file logs on repeated scans)
LOG_OPTS=(--log-driver local --log-opt max-size=10m --log-opt max-file=3)

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}[ERROR] Docker is not installed.${NC}"
        echo "Please install Docker first: curl -fsSL https://get.docker.com | sh"
        exit 1
    fi
}

deploy_target_windows() {
    echo -e "${YELLOW}[*] Installing target-windows (.30) - SMB Server...${NC}"
    docker rm -f target-windows 2>/dev/null

    sudo mkdir -p /srv/lab_smb/Public
    sudo chown -R "$(id -u):$(id -g)" /srv/lab_smb

    docker run -d --name target-windows --net "$LAB_NET" --ip 172.20.0.30 \
        "${LOG_OPTS[@]}" \
        -v /srv/lab_smb/Public:/share/public \
        elswork/samba \
        -u "$(id -u):$(id -g):docker:docker:password123" \
        -s "Public:/share/public:rw:docker"
}

create_network() {
    if ! docker network ls | grep -q "$LAB_NET"; then
        echo -e "${GREEN}[+] Creating network $LAB_NET ($LAB_SUBNET)...${NC}"
        docker network create --subnet "$LAB_SUBNET" --gateway "$LAB_GATEWAY" "$LAB_NET"
    else
        echo -e "${GREEN}[+] Network $LAB_NET already exists.${NC}"
    fi
}

install_targets() {
    check_docker
    create_network

    echo -e "${GREEN}[+] Provisioning Lab Targets...${NC}"

    # === CORE GROUP (Web & Legacy) ===

    # .10 Juice Shop (Web/Node.js)
    echo -e "${YELLOW}[*] Installing juiceshop (.10)...${NC}"
    docker run -d --name juiceshop --net "$LAB_NET" --ip 172.20.0.10 \
        "${LOG_OPTS[@]}" \
        bkimminich/juice-shop >/dev/null 2>&1 || echo "juiceshop exists"

    # .11 Metasploitable (Legacy Linux)
    echo -e "${YELLOW}[*] Installing metasploitable (.11)...${NC}"
    docker run -d --name metasploitable --net "$LAB_NET" --ip 172.20.0.11 -t \
        "${LOG_OPTS[@]}" \
        tleemcjr/metasploitable2 >/dev/null 2>&1 || echo "metasploitable exists"

    # .12 DVWA (PHP/SQLi)
    echo -e "${YELLOW}[*] Installing dvwa (.12)...${NC}"
    docker run -d --name dvwa --net "$LAB_NET" --ip 172.20.0.12 \
        "${LOG_OPTS[@]}" \
        vulnerables/web-dvwa >/dev/null 2>&1 || echo "dvwa exists"

    # .13 WebGoat (Java/OWASP)
    echo -e "${YELLOW}[*] Installing webgoat (.13)...${NC}"
    docker run -d --name webgoat --net "$LAB_NET" --ip 172.20.0.13 \
        "${LOG_OPTS[@]}" \
        webgoat/webgoat >/dev/null 2>&1 || echo "webgoat exists"

    # .14 Hackazon (E-commerce)
    echo -e "${YELLOW}[*] Installing hackazon (.14)...${NC}"
    docker run -d --name hackazon --net "$LAB_NET" --ip 172.20.0.14 \
        "${LOG_OPTS[@]}" \
        ianwijaya/hackazon >/dev/null 2>&1 || echo "hackazon exists"

    # .15 bWAPP (Buggy App)
    echo -e "${YELLOW}[*] Installing bwapp (.15)...${NC}"
    docker run -d --name bwapp --net "$LAB_NET" --ip 172.20.0.15 \
        "${LOG_OPTS[@]}" \
        raesene/bwapp >/dev/null 2>&1 || echo "bwapp exists"

    # === PHASE 4 GROUP (SSH, SMB, SNMP, AD, SCADA, IoT) ===

    # .20 SSH Target (linuxserver/openssh-server with password auth)
    echo -e "${YELLOW}[*] Installing target-ssh-lynis (.20)...${NC}"
    docker run -d --name target-ssh-lynis --net "$LAB_NET" --ip 172.20.0.20 \
        "${LOG_OPTS[@]}" \
        -e PUID=1000 -e PGID=1000 \
        -e USER_NAME=auditor -e USER_PASSWORD=redaudit \
        -e PASSWORD_ACCESS=true \
        linuxserver/openssh-server >/dev/null 2>&1 || echo "target-ssh-lynis exists"

    # .30 SMB Server (RedAudit v4.5.18 Hotfix: Force recreate with correct Samba config)
    deploy_target_windows

    # .40 SNMP v3 Target
    echo -e "${YELLOW}[*] Installing target-snmp (.40)...${NC}"
    docker run -d --name target-snmp --net "$LAB_NET" --ip 172.20.0.40 \
        "${LOG_OPTS[@]}" \
        polinux/snmpd >/dev/null 2>&1 || echo "target-snmp exists"

    # .50 OpenPLC (SCADA/Modbus)
    echo -e "${YELLOW}[*] Installing openplc-scada (.50)...${NC}"
    docker run -d --name openplc-scada --net "$LAB_NET" --ip 172.20.0.50 \
        "${LOG_OPTS[@]}" \
        -p 8443:8443 ghcr.io/autonomy-logic/openplc-runtime:latest \
        >/dev/null 2>&1 || echo "openplc-scada exists"

    # .51 Conpot (ICS Honeypot)
    echo -e "${YELLOW}[*] Installing conpot-ics (.51)...${NC}"
    docker run -d --name conpot-ics --net "$LAB_NET" --ip 172.20.0.51 \
        "${LOG_OPTS[@]}" \
        honeynet/conpot:latest >/dev/null 2>&1 || echo "conpot-ics exists"

    # .60 Samba AD DC (nowsci/samba-domain with correct env vars)
    echo -e "${YELLOW}[*] Installing samba-ad (.60) - AD DC (takes 3-5 min)...${NC}"
    docker volume create samba_ad_data >/dev/null 2>&1
    docker volume create samba_ad_cfg >/dev/null 2>&1
    docker run -d --name samba-ad --hostname dc1 --privileged \
        --net "$LAB_NET" --ip 172.20.0.60 \
        "${LOG_OPTS[@]}" \
        -e "DOMAIN=REDAUDITAD.LABORATORIO.LAN" \
        -e "DOMAINPASS=P@ssw0rd123" \
        -e "HOSTIP=172.20.0.60" \
        -e "DNSFORWARDER=8.8.8.8" \
        -v samba_ad_data:/var/lib/samba \
        -v samba_ad_cfg:/etc/samba/external \
        --dns 172.20.0.60 --dns 8.8.8.8 \
        --dns-search redauditad.laboratorio.lan \
        nowsci/samba-domain >/dev/null 2>&1 || echo "samba-ad exists"

    # .70 IoT Camera (GoAhead RCE)
    echo -e "${YELLOW}[*] Installing iot-camera (.70)...${NC}"
    docker run -d --name iot-camera --net "$LAB_NET" --ip 172.20.0.70 \
        "${LOG_OPTS[@]}" \
        vulhub/goahead:3.6.4 >/dev/null 2>&1 || echo "iot-camera exists"

    # .71 IoT Router (Web vuln placeholder)
    echo -e "${YELLOW}[*] Installing iot-router (.71)...${NC}"
    docker run -d --name iot-router --net "$LAB_NET" --ip 172.20.0.71 \
        "${LOG_OPTS[@]}" \
        webgoat/webgoat >/dev/null 2>&1 || echo "iot-router exists"

    echo -e "${GREEN}[OK] All targets installed. Run './setup_lab.sh status' to check.${NC}"
    echo -e "${YELLOW}[!] Note: samba-ad (.60) takes 3-5 minutes for first provisioning.${NC}"
}

start_lab() {
    check_docker
    echo -e "${GREEN}[+] Starting all containers in $LAB_NET...${NC}"
    containers=()
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            containers+=("$line")
        fi
    done < <(docker ps -aq --filter "network=$LAB_NET")
    if [[ ${#containers[@]} -gt 0 ]]; then
        docker start "${containers[@]}" 2>/dev/null
    fi
    echo -e "${GREEN}[OK] Lab started.${NC}"
}

stop_lab() {
    check_docker
    echo -e "${GREEN}[+] Stopping all containers in $LAB_NET...${NC}"
    containers=()
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            containers+=("$line")
        fi
    done < <(docker ps -aq --filter "network=$LAB_NET")
    if [[ ${#containers[@]} -gt 0 ]]; then
        docker stop "${containers[@]}" 2>/dev/null
    fi
    echo -e "${GREEN}[OK] Lab stopped.${NC}"
}

remove_lab() {
    check_docker
    echo -e "${RED}[!] WARNING: This will remove all lab containers and volumes.${NC}"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        containers=()
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                containers+=("$line")
            fi
        done < <(docker ps -aq --filter "network=$LAB_NET")
        if [[ ${#containers[@]} -gt 0 ]]; then
            docker rm -f "${containers[@]}" 2>/dev/null
        fi
        docker network rm "$LAB_NET" 2>/dev/null
        docker volume rm samba_ad_data samba_ad_cfg 2>/dev/null
        sudo rm -rf /srv/lab_smb 2>/dev/null
        echo -e "${GREEN}[OK] Lab removed.${NC}"
    fi
}

status_lab() {
    check_docker
    echo -e "${GREEN}=== RedAudit Lab Status ===${NC}"
    echo -e "Network: $LAB_NET ($LAB_SUBNET)"
    echo
    docker ps -a --filter "network=$LAB_NET" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo
    echo -e "Ping Check:"
    for ip in 10 11 12 13 14 15 20 30 40 50 51 60 70 71; do
        target="172.20.0.$ip"
        if ping -c1 -W1 "$target" &>/dev/null; then
             echo -e "  $target: ${GREEN}UP${NC}"
        else
             echo -e "  $target: ${RED}DOWN${NC}"
        fi
    done
}

case "$1" in
    install)
        install_targets
        ;;
    start)
        start_lab
        ;;
    stop)
        stop_lab
        ;;
    remove)
        remove_lab
        ;;
    status)
        status_lab
        ;;
    *)
        echo "Usage: $0 {install|start|stop|remove|status}"
        exit 1
        ;;
esac
