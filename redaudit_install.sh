#!/bin/bash
# RedAudit Installer (Clean install + Language injection + Alias setup)
# GPLv3 - 2025 © Dorin Badea

# -------------------------------------------
# 0) Pre-checks
# -------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDAUDIT_VERSION="$(cat "$SCRIPT_DIR/redaudit/VERSION" 2>/dev/null || echo "unknown")"

if ! command -v apt >/dev/null 2>&1; then
    echo "❌ Error: This installer requires Debian/Kali with apt."
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "❌ Error: Run this script with sudo."
    exit 1
fi

AUTO_YES=false
[[ "$1" == "-y" ]] && AUTO_YES=true

# Support non-interactive mode via environment variables (for auto-update)
# REDAUDIT_AUTO_UPDATE=1 enables fully non-interactive install
# REDAUDIT_LANG=en|es sets language without prompting
if [[ -n "$REDAUDIT_AUTO_UPDATE" ]]; then
    AUTO_YES=true
fi

# Toolchain install policy: pinned (default) or latest
TOOLCHAIN_MODE="${REDAUDIT_TOOLCHAIN_MODE:-pinned}"
if [[ "$TOOLCHAIN_MODE" != "latest" ]]; then
    TOOLCHAIN_MODE="pinned"
fi

# Determine real user early (before any operations that need it)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
USER_SHELL=$(getent passwd "$REAL_USER" | cut -d: -f7)

# -------------------------------------------
# 1) Language selector
# -------------------------------------------

# Use REDAUDIT_LANG env var if set, otherwise prompt
if [[ -n "$REDAUDIT_LANG" ]]; then
    if [[ "$REDAUDIT_LANG" == "es" ]]; then
        LANG_OPT="2"
    else
        LANG_OPT="1"
    fi
elif $AUTO_YES; then
    # Default to English in auto mode
    LANG_OPT="1"
else
    echo "----------------------------------------------"
    echo " Select Language / Selecciona Idioma"
    echo "----------------------------------------------"
    echo " 1. English"
    echo " 2. Español"
    echo "----------------------------------------------"
    read -r -p "Choice [1/2]: " LANG_OPT
    [[ -z "$LANG_OPT" ]] && LANG_OPT="1"
fi

if [[ "$LANG_OPT" == "2" ]]; then
    LANG_CODE="es"
    MSG_INSTALL="[INFO] Instalando/actualizando RedAudit v${REDAUDIT_VERSION}..."
    MSG_DONE="[OK] Instalación completada."
    MSG_USAGE="-> Ejecuta 'redaudit' para iniciar."
    MSG_ALIAS_ADDED="[INFO] Alias 'redaudit' añadido en"
    MSG_ALIAS_EXISTS="[INFO] Alias 'redaudit' ya existe en"
    MSG_PKGS="[RECOMENDADO] Instalar toolchain principal (nmap, nuclei, whatweb, nikto, tcpdump, etc.):"
    MSG_TESTSSL_NOTE="Incluye instalación de testssl.sh desde GitHub (requerido para análisis TLS profundo)."
    MSG_ASK="¿Instalar ahora? [S/n]: "
    MSG_TESTSSL_SKIP="[WARN] testssl.sh no instalado. Los análisis TLS profundos no estarán disponibles."
    MSG_TESTSSL_HINT="Ejecuta de nuevo el instalador y acepta el toolchain principal para habilitarlo."
    MSG_APT_ERR="[ERROR] Error con apt."
else
    LANG_CODE="en"
    MSG_INSTALL="[INFO] Installing/updating RedAudit v${REDAUDIT_VERSION}..."
    MSG_DONE="[OK] Installation completed."
    MSG_USAGE="-> Run 'redaudit' to start."
    MSG_ALIAS_ADDED="[INFO] Alias 'redaudit' added to"
    MSG_ALIAS_EXISTS="[INFO] Alias 'redaudit' already exists in"
    MSG_PKGS="[RECOMMENDED] Install the core toolchain (nmap, nuclei, whatweb, nikto, tcpdump, etc.):"
    MSG_TESTSSL_NOTE="Includes testssl.sh install from GitHub (required for TLS deep checks)."
    MSG_ASK="Install now? [Y/n]: "
    MSG_TESTSSL_SKIP="[WARN] testssl.sh not installed. TLS deep checks will be unavailable."
    MSG_TESTSSL_HINT="Re-run the installer and accept the core toolchain to enable it."
    MSG_APT_ERR="❌ apt error."
fi

echo "$MSG_INSTALL"

# -------------------------------------------
# 2) Dependencies
# -------------------------------------------

EXTRA_PKGS="curl wget openssl nmap tcpdump tshark whois bind9-dnsutils python3-nmap python3-cryptography python3-netifaces python3-requests python3-jinja2 python3-keyring exploitdb git nbtscan netdiscover fping avahi-utils arp-scan lldpd snmp snmp-mibs-downloader enum4linux smbclient samba-common-bin masscan ldap-utils bettercap python3-scapy proxychains4 nuclei whatweb nikto sqlmap traceroute"

echo ""
echo "$MSG_PKGS"
echo "   $EXTRA_PKGS"
echo "   $MSG_TESTSSL_NOTE"

if $AUTO_YES; then
    INSTALL="y"
else
    read -r -p "$MSG_ASK" INSTALL
fi

INSTALL=${INSTALL,,}
if [[ "$LANG_CODE" == "es" ]]; then
    [[ -z "$INSTALL" || "$INSTALL" =~ ^(s|si|y|yes)$ ]] && INSTALL=true || INSTALL=false
else
    [[ -z "$INSTALL" || "$INSTALL" =~ ^(y|yes)$ ]] && INSTALL=true || INSTALL=false
fi

if $INSTALL; then
    read -r -a extra_pkgs <<< "$EXTRA_PKGS"
    if ! apt update; then
        echo "$MSG_APT_ERR"
        exit 1
    fi
    if ! apt install -y "${extra_pkgs[@]}"; then
        echo "$MSG_APT_ERR"
        exit 1
    fi



    # Try to install python3-pysnmp via apt (missing in some distros like Ubuntu Noble)
    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[INFO] Intentando instalar python3-pysnmp via apt (opcional)..."
    else
        echo "[INFO] Trying to install python3-pysnmp via apt (optional)..."
    fi
    apt install -y python3-pysnmp 2>/dev/null || true

    # Python packages for authenticated scanning (Phase 4: SSH/SMB/SNMP + Keyring)
    echo "[INFO] Installing Python packages for authenticated scanning..."

    PIP_PKGS="paramiko impacket pysnmp keyring keyrings.alt"
    read -r -a pip_pkgs <<< "$PIP_PKGS"
    if pip3 install "${pip_pkgs[@]}"; then
        echo "[OK] Python packages installed via pip"
    else
        echo "[WARN] Standard pip3 install failed. Checking for PEP 668 managed environment..."
        # Retry with --break-system-packages if relevant (modern Kali/Ubuntu/Debian)
        if pip3 install --help | grep -q "\-\-break\-system\-packages"; then
             echo "[INFO] Retrying with --break-system-packages (required for system-wide install on modern distros)..."
             pip3 install "${pip_pkgs[@]}" --break-system-packages || echo "[WARN] pip install failed even with break-system-packages"
        else
             echo "[WARN] pip install failed and --break-system-packages flag is not supported."
        fi
    fi

    # -------------------------------------------
    # 2b) Install testssl.sh from GitHub
    # -------------------------------------------

    TESTSSL_REPO="https://github.com/drwetter/testssl.sh.git"
    if [[ -z "${TESTSSL_VERSION+x}" ]]; then
        if [[ "$TOOLCHAIN_MODE" == "latest" ]]; then
            TESTSSL_VERSION="latest"
        else
            TESTSSL_VERSION="v3.2"
        fi
    fi

    if [[ ! -f "/usr/local/bin/testssl.sh" ]]; then
        echo "[INFO] Installing testssl.sh ($TESTSSL_VERSION) from GitHub..."
        if command -v git &> /dev/null; then
            rm -rf /opt/testssl.sh 2>/dev/null
            # Try version tag first, fallback to latest if it fails
            if [[ "$TESTSSL_VERSION" == "latest" ]]; then
                if git clone --depth 1 "$TESTSSL_REPO" /opt/testssl.sh 2>/dev/null; then
                    echo "[OK] Cloned testssl.sh (latest)"
                else
                    echo "[WARN] git clone failed; skipping testssl.sh installation"
                    rm -rf /opt/testssl.sh 2>/dev/null
                fi
            else
                if git clone --depth 1 --branch "$TESTSSL_VERSION" "$TESTSSL_REPO" /opt/testssl.sh 2>/dev/null; then
                    echo "[OK] Cloned testssl.sh $TESTSSL_VERSION"
                elif git clone --depth 1 "$TESTSSL_REPO" /opt/testssl.sh 2>/dev/null; then
                    echo "[OK] Cloned testssl.sh (latest)"
                else
                    echo "[WARN] git clone failed; skipping testssl.sh installation"
                    rm -rf /opt/testssl.sh 2>/dev/null
                fi
            fi
            # Create symlink if clone succeeded
            if [[ -f "/opt/testssl.sh/testssl.sh" ]]; then
                ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
                chmod +x /opt/testssl.sh/testssl.sh
                echo "[OK] testssl.sh installed at /usr/local/bin/testssl.sh"
            fi
        else
            echo "[WARN] git not found, skipping testssl.sh installation"
        fi
    else
        echo "[OK] testssl.sh already installed"
    fi
else
    if [[ -f "/usr/local/bin/testssl.sh" || -f "/opt/testssl.sh/testssl.sh" || -f "/usr/bin/testssl.sh" ]]; then
        echo "[OK] testssl.sh already installed"
    else
        echo "$MSG_TESTSSL_SKIP"
        echo "$MSG_TESTSSL_HINT"
    fi
fi


# -------------------------------------------
# 2c) Install kerbrute (Red Team / Kerberos)
# -------------------------------------------

if [[ ! -f "/usr/local/bin/kerbrute" ]]; then
    if [[ -z "${KERBRUTE_VERSION+x}" ]]; then
        if [[ "$TOOLCHAIN_MODE" == "latest" ]]; then
            KERBRUTE_VERSION="latest"
        else
            KERBRUTE_VERSION="v1.0.3"
        fi
    fi
    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[INFO] Instalando kerbrute (${KERBRUTE_VERSION})..."
    else
        echo "[INFO] Installing kerbrute (${KERBRUTE_VERSION})..."
    fi
    if [[ "$KERBRUTE_VERSION" == "latest" ]]; then
        KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
    else
        KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/download/${KERBRUTE_VERSION}/kerbrute_linux_amd64"
    fi
    if wget -q -O /usr/local/bin/kerbrute "$KERBRUTE_URL"; then
        chmod +x /usr/local/bin/kerbrute
        if [[ "$LANG_CODE" == "es" ]]; then
            echo "[OK] kerbrute instalado en /usr/local/bin/kerbrute"
        else
            echo "[OK] kerbrute installed at /usr/local/bin/kerbrute"
        fi
    else
        if [[ "$LANG_CODE" == "es" ]]; then
            echo "[WARN] Falló la descarga de kerbrute desde GitHub. Se omite."
        else
            echo "[WARN] Failed to download kerbrute from GitHub. Skipping."
        fi
    fi
else
    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[OK] kerbrute ya instalado"
    else
        echo "[OK] kerbrute already installed"
    fi
fi

# -------------------------------------------
# 2d) Install OWASP ZAP (apt for Kali/Debian, snap for Ubuntu)
# -------------------------------------------

# -------------------------------------------
# 2e) Install RustScan (fast port scanner)
# -------------------------------------------

if [[ -z "${RUSTSCAN_VERSION+x}" ]]; then
    RUSTSCAN_VERSION="2.3.0"
fi

if ! command -v rustscan &> /dev/null; then
    # Detect Architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            DEB_ARCH="amd64"
            ;;
        aarch64|arm64)
            # RustScan 2.3.0 does not consistently provide a .deb for aarch64 on the main release page.
            # However, for robustness, we will try to fetch if available or fallback.
            # IMPORTANT: For v2.3.0, only amd64 .deb is standard.
            # If we are on ARM, we might need to skip or warn if no .deb exists.
            DEB_ARCH="aarch64"
            ;;
        *)
            DEB_ARCH="unknown"
            ;;
    esac

    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[INFO] Instalando RustScan v${RUSTSCAN_VERSION}..."
    else
        echo "[INFO] Installing RustScan v${RUSTSCAN_VERSION}..."
    fi

    # NOTE: As of 2024/2025, RustScan release assets for ARM .deb are not always guaranteed
    # compatible or consistent in naming (sometimes zip).
    # For now, we only support amd64 officially via .deb.
    # For ARM/Kali-ARM/Pi, we fallback to nmap to avoid breaking the install.

    if [[ "$DEB_ARCH" == "amd64" ]]; then
        RUSTSCAN_DEB="/tmp/rustscan_${RUSTSCAN_VERSION}_amd64.deb"
        RUSTSCAN_URL="https://github.com/RustScan/RustScan/releases/download/${RUSTSCAN_VERSION}/rustscan_${RUSTSCAN_VERSION}_amd64.deb"

        if wget -q -O "$RUSTSCAN_DEB" "$RUSTSCAN_URL" 2>/dev/null; then
            if dpkg -i "$RUSTSCAN_DEB" 2>/dev/null; then
                 if [[ "$LANG_CODE" == "es" ]]; then echo "[OK] RustScan instalado"; else echo "[OK] RustScan installed"; fi
            else
                 if [[ "$LANG_CODE" == "es" ]]; then echo "[WARN] Falló la instalación del .deb. Usando nmap."; else echo "[WARN] .deb install failed. Using nmap."; fi
            fi
            rm -f "$RUSTSCAN_DEB" 2>/dev/null
        else
            if [[ "$LANG_CODE" == "es" ]]; then echo "[WARN] Falló descarga. Usando nmap."; else echo "[WARN] Download failed. Using nmap."; fi
        fi
    else
        # Non-amd64 architecture
        if [[ "$LANG_CODE" == "es" ]]; then
            echo "[WARN] Arquitectura $ARCH detectada. RustScan .deb solo disponible para amd64."
            echo "       Usando nmap como fallback (más lento pero compatible)."
        else
            echo "[WARN] Architecture $ARCH detected. RustScan .deb checks only support amd64."
            echo "       Using nmap as fallback (slower but compatible)."
        fi
    fi
else
    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[OK] RustScan ya instalado ($(rustscan --version 2>/dev/null | head -1 || echo 'version unknown'))"
    else
        echo "[OK] RustScan already installed ($(rustscan --version 2>/dev/null | head -1 || echo 'version unknown'))"
    fi
fi

# -------------------------------------------
# 2f) Install OWASP ZAP (apt for Kali/Debian, snap for Ubuntu)
# -------------------------------------------

if ! command -v zap.sh >/dev/null 2>&1 && ! command -v zaproxy >/dev/null 2>&1; then
    ZAP_INSTALLED=false

    # Try apt first (works on Kali, Debian with backports)
    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[INFO] Intentando instalar ZAP via apt..."
    else
        echo "[INFO] Attempting to install ZAP via apt..."
    fi

    if apt install -y zaproxy 2>/dev/null; then
        ZAP_INSTALLED=true
        if [[ "$LANG_CODE" == "es" ]]; then
            echo "[OK] ZAP instalado via apt"
        else
            echo "[OK] ZAP installed via apt"
        fi
    else
        # apt failed (Ubuntu Noble), try snap
        if [[ "$LANG_CODE" == "es" ]]; then
            echo "[INFO] apt falló, intentando via snap..."
        else
            echo "[INFO] apt failed, trying snap..."
        fi

        if command -v snap >/dev/null 2>&1; then
            if snap install zaproxy --classic 2>/dev/null; then
                ZAP_INSTALLED=true
                # Create symlink for zap.sh detection
                if [[ -f "/snap/bin/zaproxy" ]]; then
                    ln -sf /snap/bin/zaproxy /usr/local/bin/zap.sh 2>/dev/null || true
                fi
                if [[ "$LANG_CODE" == "es" ]]; then
                    echo "[OK] ZAP instalado via snap"
                else
                    echo "[OK] ZAP installed via snap"
                fi
            fi
        fi
    fi

    if ! $ZAP_INSTALLED; then
        if [[ "$LANG_CODE" == "es" ]]; then
            echo "[WARN] No se pudo instalar ZAP. Instalación manual requerida."
            echo "       Ubuntu: sudo snap install zaproxy --classic"
            echo "       Kali/Debian: sudo apt install zaproxy"
        else
            echo "[WARN] Could not install ZAP. Manual installation required."
            echo "       Ubuntu: sudo snap install zaproxy --classic"
            echo "       Kali/Debian: sudo apt install zaproxy"
        fi
    fi
else
    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[OK] ZAP ya instalado"
    else
        echo "[OK] ZAP already installed"
    fi
fi

# -------------------------------------------
# 3) Install redaudit package --> /usr/local/lib/redaudit
# -------------------------------------------

SCRIPT_SRC="$SCRIPT_DIR/redaudit.py"
PACKAGE_SRC="$SCRIPT_DIR/redaudit"

if [[ ! -f "$SCRIPT_SRC" ]]; then
    echo "Error: redaudit.py not found next to installer!"
    echo "Place redaudit_install.sh and redaudit.py in the same directory."
    exit 1
fi

# Install the package if it exists (v2.6+ modular structure)
if [[ -d "$PACKAGE_SRC" ]]; then
    # Remove old package installation
    rm -rf /usr/local/lib/redaudit

    # Copy the package
    cp -r "$PACKAGE_SRC" /usr/local/lib/redaudit
    chmod -R 755 /usr/local/lib/redaudit

    # Inject selected language into constants.py
    CONSTANTS_FILE="/usr/local/lib/redaudit/utils/constants.py"
    if [[ -f "$CONSTANTS_FILE" ]]; then
        sed -i "s/^DEFAULT_LANG = .*/DEFAULT_LANG = \"$LANG_CODE\"/" "$CONSTANTS_FILE"
        echo "Language set to: $LANG_CODE"
    fi

    echo "Package installed at /usr/local/lib/redaudit"
fi

# Install the wrapper script
TEMP_SCRIPT=$(mktemp)
cp "$SCRIPT_SRC" "$TEMP_SCRIPT"

# Inject selected language (for backward compatibility with monolithic script)
sed -i "s/^DEFAULT_LANG = .*/DEFAULT_LANG = \"$LANG_CODE\"/" "$TEMP_SCRIPT" 2>/dev/null || true

# Move into the system
mv "$TEMP_SCRIPT" /usr/local/bin/redaudit
chmod 755 /usr/local/bin/redaudit
chown root:root /usr/local/bin/redaudit

echo "Wrapper installed at /usr/local/bin/redaudit"

# -------------------------------------------
# 3b) NVD API Key Setup (Optional)
# -------------------------------------------

if [[ "$LANG_CODE" == "es" ]]; then
    MSG_NVD_HEADER="CONFIGURACIÓN DE API KEY DE NVD (Opcional)"
    MSG_NVD_INFO="La correlación CVE requiere una API key de NVD para consultas más rápidas."
    MSG_NVD_RATE="Sin key: 5 peticiones/30s | Con key: 50 peticiones/30s"
    MSG_NVD_REG="Regístrate GRATIS en: https://nvd.nist.gov/developers/request-an-api-key"
    MSG_NVD_ASK="Introduce tu API key (o ENTER para omitir): "
    MSG_NVD_SAVED="✓ API key guardada en"
    MSG_NVD_SKIP="API key omitida. Puedes configurarla después."
else
    MSG_NVD_HEADER="NVD API KEY SETUP (Optional)"
    MSG_NVD_INFO="CVE correlation requires an NVD API key for faster lookups."
    MSG_NVD_RATE="Without key: 5 requests/30s | With key: 50 requests/30s"
    MSG_NVD_REG="Register for FREE at: https://nvd.nist.gov/developers/request-an-api-key"
    MSG_NVD_ASK="Enter your API key (or ENTER to skip): "
    MSG_NVD_SAVED="✓ API key saved to"
    MSG_NVD_SKIP="API key skipped. You can configure it later."
fi

echo ""
echo "----------------------------------------------"
echo " $MSG_NVD_HEADER"
echo "----------------------------------------------"
echo "$MSG_NVD_INFO"
echo "$MSG_NVD_RATE"
echo ""
echo "$MSG_NVD_REG"
echo ""

if $AUTO_YES; then
    NVD_KEY=""
else
    read -r -p "$MSG_NVD_ASK" NVD_KEY
fi

if [[ -n "$NVD_KEY" ]]; then
    # Validate UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    if [[ "$NVD_KEY" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        CONFIG_DIR="$REAL_HOME/.redaudit"
        CONFIG_FILE="$CONFIG_DIR/config.json"
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        echo "{\"version\": \"${REDAUDIT_VERSION}\", \"nvd_api_key\": \"$NVD_KEY\", \"nvd_api_key_storage\": \"config\"}" > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
        chown "$REAL_USER:$REAL_USER" "$CONFIG_DIR" "$CONFIG_FILE"
        echo "$MSG_NVD_SAVED $CONFIG_FILE"
    else
        echo "⚠️  Invalid API key format (expected UUID). Skipping."
    fi
else
    echo "$MSG_NVD_SKIP"
fi

# -------------------------------------------
# 4) Alias setup
# -------------------------------------------

# (REAL_USER, REAL_HOME, USER_SHELL already defined at top of script)

RC_FILE="$REAL_HOME/.bashrc"
[[ "$USER_SHELL" == *"zsh"* ]] && RC_FILE="$REAL_HOME/.zshrc"

if [[ -w "$RC_FILE" ]]; then
    if ! grep -q "alias redaudit=" "$RC_FILE" 2>/dev/null; then
        echo "alias redaudit='sudo /usr/local/bin/redaudit'" >> "$RC_FILE"
        chown "$REAL_USER" "$RC_FILE"
        echo "$MSG_ALIAS_ADDED $RC_FILE"
    else
        echo "$MSG_ALIAS_EXISTS $RC_FILE"
    fi
else
    echo "[WARN] Could not write alias to $RC_FILE (permissions)."
fi


# Create the specific source command message based on the shell
if [[ "$RC_FILE" == *".zshrc" ]]; then
    SOURCE_CMD="source ~/.zshrc"
else
    SOURCE_CMD="source ~/.bashrc"
fi

echo ""
echo "$MSG_DONE"

# Show git commit hash for version confirmation
GIT_COMMIT=""
if [[ -d "$SCRIPT_DIR/.git" ]] && command -v git >/dev/null 2>&1; then
    GIT_COMMIT=$(cd "$SCRIPT_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "")
fi
if [[ -n "$GIT_COMMIT" ]]; then
    if [[ "$LANG_CODE" == "es" ]]; then
        echo "[INFO] Commit instalado: $GIT_COMMIT (rama: $(cd "$SCRIPT_DIR" && git branch --show-current 2>/dev/null || echo "unknown"))"
    else
        echo "[INFO] Installed commit: $GIT_COMMIT (branch: $(cd "$SCRIPT_DIR" && git branch --show-current 2>/dev/null || echo "unknown"))"
    fi
fi

if [[ "$LANG_CODE" == "es" ]]; then
    echo ""
    echo "IMPORTANTE: Para usar 'redaudit' inmediatamente, ejecuta:"
    echo "   $SOURCE_CMD"
    echo ""
    echo "(O simplemente abre una nueva terminal)"
    echo ""
    echo "$MSG_USAGE"
else
    echo ""
    echo "IMPORTANT: To use 'redaudit' immediately, run:"
    echo "   $SOURCE_CMD"
    echo ""
    echo "(Or simply open a new terminal)"
    echo ""
    echo "$MSG_USAGE"
fi
