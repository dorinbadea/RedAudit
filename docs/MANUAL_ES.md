Manual de instalación de RedAudit v2.3

**Rol:** Pentester / Programador Senior

## 1. Requisitos previos

**Sistema objetivo:**
*   Kali Linux (o distro similar basada en Debian)
*   Usuario con `sudo` configurado
*   Conexión a Internet para instalar paquetes

**Paquetes usados:**
El instalador puede instalar automáticamente el pack recomendado si se solicita (modo interactivo o flag `-y`).

*   **Core (Requerido):** `nmap`, `python3-nmap`
*   **Recomendado (Opcional):** `whatweb`, `nikto`, `curl`, `wget`, `openssl`, `tcpdump`, `tshark`, `whois`, `bind9-dnsutils`

Para instalar manualmente:
```bash
sudo apt update
sudo apt install -y nmap python3-nmap whatweb nikto curl wget openssl tcpdump tshark whois bind9-dnsutils
```

> **Nota:** `nmap` y `python3-nmap` son críticos. El resto se recomiendan para aprovechar todas las funciones (escáner web, captura de tráfico, enriquecimiento DNS).

*   **Deep Scan Automático:** RedAudit detecta automáticamente hosts "tímidos" o sospechosos y lanza un escaneo profundo (`-A -p- -sV`) que incluye captura de paquetes para identificar firewalls o servicios ocultos.

---

## 2. Preparar carpeta de trabajo

Usamos una carpeta estándar para herramientas:

```bash
mkdir -p ~/herramientas_seguridad
cd ~/herramientas_seguridad
```

---

## 3. Instalación

1.  Clonar el repositorio:
    ```bash
    git clone https://github.com/dorinbad/RedAudit.git
    cd RedAudit
    ```

2.  Ejecutar el instalador:
    ```bash
    chmod +x redaudit_install.sh
    sudo ./redaudit_install.sh
    
    # O para instalación no interactiva:
    # sudo ./redaudit_install.sh -y
    ```

El instalador se encargará de:
1.  Ofrecer la instalación de utilidades de red recomendadas.
2.  Instalar RedAudit en `/usr/local/bin/redaudit`.
3.  Configurar el alias necesario en tu shell.

---

## 4. Activar el alias en tu shell

Tras la instalación:

```bash
source ~/.bashrc  # O ~/.zshrc si usas ZSH
```

A partir de aquí, en cualquier terminal de tu usuario normal:

```bash
redaudit
```

---

## 5. Endurecimiento y Seguridad

RedAudit v2.3 incluye nuevas características para garantizar una operación segura:

*   **Sanitización de Entrada**: Validación estricta de IPs y nombres de interfaz para evitar inyección de comandos.
*   **Cifrado de Reportes**: Opción para cifrar los resultados (JSON y TXT) usando Fernet (AES). Requiere `python3-cryptography`.
*   **Rate Limiting**: Retardo configurable entre hosts para reducir el ruido en la red.
*   **Logging**: Registros de auditoría detallados y rotativos en `~/.redaudit/logs`.

Para descifrar reportes:
```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

---

## 6. Verificación rápida

Comandos útiles para comprobar que todo está en su sitio:

```bash
# Dónde está el binario
which redaudit
# → debe apuntar a /usr/local/bin/redaudit (vía alias)

# Ver permisos del binario
ls -l /usr/local/bin/redaudit

# Confirmar alias
grep "alias redaudit" ~/.bashrc
# (o ~/.zshrc)
```

---

## 7. Actualizar RedAudit a una nueva versión

Cuando quieras actualizar el código (por ejemplo, pasar de 2.3 a 2.4):
1.  Editas el instalador con el código nuevo (git pull).
2.  Lo ejecutas de nuevo:

    ```bash
    sudo ./redaudit_install.sh
    source ~/.bashrc
    ```

El binario `/usr/local/bin/redaudit` se sobrescribe con la nueva versión.

---

## 8. Desinstalación (por si hace falta)

Eliminar binario y alias:

```bash
sudo rm -f /usr/local/bin/redaudit
sed -i '/alias redaudit=/d' ~/.bashrc  # O ~/.zshrc
source ~/.bashrc
```
