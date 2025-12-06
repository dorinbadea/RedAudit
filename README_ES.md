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

**RedAudit** es una herramienta de auditoría de red interactiva y automatizada diseñada para Kali Linux y sistemas Debian. Agiliza el proceso de reconocimiento combinando descubrimiento de red, escaneo de puertos y evaluación de vulnerabilidades en un flujo de trabajo CLI único y fácil de usar.

## 🖥️ Vista Previa

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

## 🚀 Características

*   **CLI Interactiva:** Menús amigables para configuración y ejecución.
*   **Descubrimiento Inteligente:** Detecta automáticamente redes e interfaces locales.
*   **Escaneo Multimodo:**
    *   **RÁPIDO (Fast):** Solo descubrimiento (`-sn`), sin escaneo de puertos, bajo ruido.
    *   **NORMAL:** Puertos principales + Versionado de servicios (`-F -sV`). Equilibrio velocidad/cobertura.
    *   **COMPLETO (Full):** Todos los puertos (`-p-`) + Scripts + Análisis de Vulns + Web.
*   **Deep Scans Automatizados:** Lanza automáticamente escaneos agresivos (`-A -sV -Pn` + UDP) y captura de tráfico (`tcpdump`) para hosts sospechosos o que no responden.
*   **Análisis Web:** Integra `whatweb`, `nikto` (recomendados) para reconocimiento de servicios web.
*   **Resiliencia:** Incluye monitor de actividad (heartbeat) y manejo de señales para escaneos largos.
*   **Reportes:** Genera reportes detallados en JSON y TXT en `~/RedAuditReports` (o carpeta personalizada).

## 📦 Dependencias

RedAudit está diseñado para **sistemas basados en apt** (Kali, Debian, Ubuntu).

### Requeridas (Core)
Críticas para el funcionamiento básico:
*   `nmap` (Motor de escaneo principal)
*   `python3-nmap` (Librería Python para Nmap)

### Recomendadas (Enriquecimiento)
Opcionales pero muy recomendadas para funcionalidad completa (Web, Tráfico, DNS):
*   `whatweb`
*   `nikto`
*   `curl`, `wget`, `openssl`
*   `tcpdump`, `tshark`
*   `whois`, `bind9-dnsutils` (para `dig`)

Para instalar todo manualmente:
```bash
sudo apt update
sudo apt install nmap python3-nmap whatweb nikto curl wget openssl tcpdump tshark whois bind9-dnsutils
```

## 🏗️ Arquitectura y Flujo

1.  **Inicialización:** El script detecta interfaces de red y solicita objetivos al usuario.
2.  **Descubrimiento:** Ejecuta un discovery rápido de Nmap (`-sn`) en los rangos seleccionados.
3.  **Escaneo de Hosts:**
    *   Itera sobre los hosts activos usando hilos concurrentes.
    *   Ejecuta el modo seleccionado (RÁPIDO/NORMAL/COMPLETO).
    *   **Lógica Deep Scan:** Si un host arroja pocos resultados o errores, se lanza un Deep Scan especializado automáticamente.
4.  **Enriquecimiento:**
    *   **Web:** Si detecta HTTP/HTTPS, lanza WhatWeb y Nikto (si está activado).
    *   **Tráfico:** Si `tcpdump` está disponible, captura una pequeña muestra de tráfico para análisis.
    *   **DNS/Whois:** Resuelve IPs públicas.
5.  **Reportes:** Todos los datos se agregan en reportes JSON y TXT en el directorio de salida.

## 🛠️ Instalación

RedAudit v2.3 usa un instalador Bash que envuelve el núcleo en Python.

1.  Clona el repositorio:
    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.  Ejecuta el instalador (como **root**):
    ```bash
    chmod +x redaudit_install.sh
    
    # Instalación interactiva (pregunta por herramientas recomendadas)
    sudo bash redaudit_install.sh
    
    # Modo no interactivo (instala herramientas recomendadas automáticamente)
    sudo bash redaudit_install.sh -y
    ```

3.  Recarga tu shell para usar el alias `redaudit`:
    ```bash
    source ~/.bashrc  # O ~/.zshrc
    ```

## 💻 Uso

Una vez instalado, simplemente ejecuta:

```bash
redaudit
```

Sigue el asistente interactivo:
1.  **Seleccionar Red**: Elige una red local detectada o introduce un CIDR manual.
2.  **Modo de Escaneo**:
    *   **RÁPIDO**: Solo descubrimiento.
    *   **NORMAL**: Reconocimiento estándar.
    *   **COMPLETO**: Auditoría exhaustiva.
3.  **Opciones**: Define hilos, activa escaneo web, elige directorio de salida.
4.  **Autorización**: Confirma que tienes permiso para escanear el objetivo.

## ⚠️ Aviso Legal y Ético

**RedAudit es una herramienta de seguridad para uso exclusivamente autorizado.**

Escanear redes o sistemas sin permiso explícito es ilegal y punishable por ley.
*   **No uses** esta herramienta en redes que no seas dueño o tengas consentimiento escrito para auditar.
*   **No uses** esta herramienta para fines maliciosos.

Los desarrolladores no asumen ninguna responsabilidad por el mal uso de este software. El usuario es el único responsable de cumplir con las leyes locales, estatales y federales aplicables.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.
