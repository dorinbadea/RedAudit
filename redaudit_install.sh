#!/bin/bash
# RedAudit Installer v3.2.3 (Clean install + Language injection + Alias setup)
# GPLv3 - 2025 © Dorin Badea

# -------------------------------------------
# 0) Pre-checks
# -------------------------------------------

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
    MSG_INSTALL="[INFO] Instalando/actualizando RedAudit v3.2.3..."
    MSG_DONE="[OK] Instalación completada."
    MSG_USAGE="-> Ejecuta 'redaudit' para iniciar."
    MSG_ALIAS_ADDED="[INFO] Alias 'redaudit' añadido en"
    MSG_ALIAS_EXISTS="[INFO] Alias 'redaudit' ya existe en"
    MSG_PKGS="[OPTIONAL] Opcional: instalar utilidades recomendadas:"
    MSG_ASK="¿Instalar ahora? [S/n]: "
    MSG_APT_ERR="[ERROR] Error con apt."
else
    LANG_CODE="en"
    MSG_INSTALL="[INFO] Installing/updating RedAudit v3.2.3..."
    MSG_DONE="[OK] Installation completed."
    MSG_USAGE="-> Run 'redaudit' to start."
    MSG_ALIAS_ADDED="ℹ️ Alias 'redaudit' added to"
    MSG_ALIAS_EXISTS="ℹ️ Alias 'redaudit' already exists in"
    MSG_PKGS="📦 Optional: install recommended utilities:"
    MSG_ASK="Install now? [Y/n]: "
    MSG_APT_ERR="❌ apt error."
fi

echo "$MSG_INSTALL"

# -------------------------------------------
# 2) Dependencies
# -------------------------------------------

EXTRA_PKGS="curl wget openssl nmap tcpdump tshark whois bind9-dnsutils python3-nmap python3-cryptography python3-netifaces exploitdb git nbtscan netdiscover fping avahi-utils arp-scan lldpd snmp snmp-mibs-downloader enum4linux smbclient masscan ldap-utils bettercap python3-scapy proxychains4"

echo ""
echo "$MSG_PKGS"
echo "   $EXTRA_PKGS"

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
    apt update && apt install -y $EXTRA_PKGS || { echo "$MSG_APT_ERR"; exit 1; }
fi

# -------------------------------------------
# 2b) Install testssl.sh from GitHub (pinned commit)
# -------------------------------------------

TESTSSL_REPO="https://github.com/drwetter/testssl.sh.git"
TESTSSL_VERSION="${TESTSSL_VERSION:-v3.2.2}"
TESTSSL_COMMIT="${TESTSSL_COMMIT:-3b6c5035bafcd0590f03730f76688bdce5568df0}"

if [[ ! -f "/usr/local/bin/testssl.sh" ]]; then
    echo "[INFO] Installing testssl.sh ($TESTSSL_VERSION, pinned) from GitHub..."
    if command -v git &> /dev/null; then
        rm -rf /opt/testssl.sh 2>/dev/null
        if git clone --depth 1 --branch "$TESTSSL_VERSION" "$TESTSSL_REPO" /opt/testssl.sh; then
            CLONED_COMMIT=$(git -C /opt/testssl.sh rev-parse HEAD 2>/dev/null || echo "unknown")
            if [[ "$CLONED_COMMIT" != "$TESTSSL_COMMIT" ]]; then
                echo "[ERROR] testssl.sh commit mismatch (expected $TESTSSL_COMMIT, got $CLONED_COMMIT). Skipping installation."
                rm -rf /opt/testssl.sh
            else
                ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
                chmod +x /opt/testssl.sh/testssl.sh
                echo "[OK] testssl.sh installed at /usr/local/bin/testssl.sh"
            fi
        else
            echo "[WARN] git clone failed; skipping testssl.sh installation"
            rm -rf /opt/testssl.sh
        fi
    else
        echo "[WARN] git not found, skipping testssl.sh installation"
    fi
else
    echo "[OK] testssl.sh already installed"
fi

# -------------------------------------------
# 2c) Install kerbrute (Red Team / Kerberos)
# -------------------------------------------

if [[ ! -f "/usr/local/bin/kerbrute" ]]; then
    echo "[INFO] Installing kerbrute (v1.0.3)..."
    KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64"
    if wget -q -O /usr/local/bin/kerbrute "$KERBRUTE_URL"; then
        chmod +x /usr/local/bin/kerbrute
        echo "[OK] kerbrute installed at /usr/local/bin/kerbrute"
    else
        echo "[WARN] Failed to download kerbrute from GitHub. Skipping."
    fi
else
    echo "[OK] kerbrute already installed"
fi

# -------------------------------------------
# 3) Install redaudit package --> /usr/local/lib/redaudit
# -------------------------------------------

SCRIPT_DIR="$(dirname "$0")"
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
        echo "{\"version\": \"3.2.3\", \"nvd_api_key\": \"$NVD_KEY\", \"nvd_api_key_storage\": \"config\"}" > "$CONFIG_FILE"
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
    SHELL_NAME="Zsh"
else
    SOURCE_CMD="source ~/.bashrc"
    SHELL_NAME="Bash"
fi

echo ""
echo "$MSG_DONE"

if [[ "$LANG_CODE" == "es" ]]; then
    echo "👉 IMPORTANTE: Para usar 'redaudit' inmediatamente, ejecuta:"
    echo "   $SOURCE_CMD"
    echo ""
    echo "(O simplemente abre una nueva terminal)"
else
    echo "👉 IMPORTANT: To use 'redaudit' immediately, run:"
    echo "   $SOURCE_CMD"
    echo ""
    echo "(Or simply open a new terminal)"
fi
