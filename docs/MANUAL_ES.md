Manual de instalación de RedAudit v2.3.1

**Rol:** Pentester / Programador Senior

## 1. Requisitos previos

**Sistema objetivo:**
*   Kali Linux (o distro similar basada en Debian)
*   Usuario con `sudo` configurado
*   Conexión a Internet para instalar paquetes

**Paquetes usados:**
El instalador puede instalar automáticamente el pack recomendado si se solicita (modo interactivo o flag `-y`).

*   **Core (Requerido):** `nmap`, `python3-nmap`, `python3-cryptography`
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

## 5. 🔒 Características de Seguridad (NUEVO en v2.3)

RedAudit v2.3 introduce un endurecimiento de seguridad de grado empresarial:

- **Sanitización de Entrada**: Todas las entradas de usuario y salidas de comandos son validadas.
- **Reportes Cifrados**: Cifrado opcional **AES-128 (Fernet)** con PBKDF2-HMAC-SHA256 (480k iteraciones).
- **Seguridad de Hilos**: Todas las operaciones concurrentes usan mecanismos de bloqueo adecuados.
- **Rate Limiting**: Retardos configurables para evitar detección y saturación de red.
- **Audit Logging**: Registro exhaustivo con rotación automática (10MB, 5 backups).

[→ Documentación de Seguridad Completa](SECURITY.md)

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
