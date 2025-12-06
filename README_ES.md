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

## 🚀 Características

*   **CLI Interactiva:** Menús amigables para configuración y ejecución.
*   **Descubrimiento Inteligente:** Detecta automáticamente redes e interfaces locales.
*   **Escaneo Multimodo:**
    *   **Rápido:** Descubrimiento veloz (ping sweep).
    *   **Normal:** Puertos principales + Versionado de servicios.
    *   **Completo:** Todos los puertos + Scripts + Chequeo de vulnerabilidades.
*   **Deep Scans Automatizados:** Lanza automáticamente escaneos agresivos y captura de tráfico (`tcpdump`) para hosts sospechosos o que no responden.
*   **Análisis Web:** Integra `whatweb`, `nikto` y `openssl` para reconocimiento de servicios web.
*   **Resiliencia:** Incluye monitor de "latido" (heartbeat) y manejo de señales para escaneos largos.
*   **Reportes:** Genera reportes detallados en JSON y TXT.

## 📋 Requisitos

*   **SO:** Kali Linux (o distros basadas en Debian).
*   **Privilegios:** Se requiere acceso Root/Sudo.
*   **Dependencias:** `nmap`, `python3-nmap`, `curl`, `wget`, `tcpdump`, `tshark`, `whois`, `bind9-dnsutils`, `whatweb`, `nikto`.

## 🛠️ Instalación

1.  Clona el repositorio:
    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.  Ejecuta el instalador:
    ```bash
    chmod +x redaudit_install.sh
    sudo ./redaudit_install.sh
    ```

3.  Recarga tu shell:
    ```bash
    source ~/.bashrc  # O ~/.zshrc si usas ZSH
    ```

## 💻 Uso

Simplemente ejecuta el comando desde cualquier terminal:

```bash
redaudit
```

Sigue las instrucciones interactivas para seleccionar tu red objetivo, intensidad de escaneo y otras opciones.

## ⚠️ Aviso Legal

**RedAudit es solo para fines educativos y pruebas autorizadas.**
El uso de esta herramienta para atacar objetivos sin consentimiento mutuo previo es ilegal. El desarrollador no asume ninguna responsabilidad y no es responsable de ningún mal uso o daño causado por este programa.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.
