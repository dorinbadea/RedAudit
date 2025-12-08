#!/bin/bash
# RedAudit Installer v2.5 (Clean install + Language injection + Alias setup)
# GPLv3 - 2026 © Dorin Badea

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

# -------------------------------------------
# 1) Language selector
# -------------------------------------------

echo "----------------------------------------------"
echo " Select Language / Selecciona Idioma"
echo "----------------------------------------------"
echo " 1. English"
echo " 2. Español"
echo "----------------------------------------------"

read -r -p "Choice [1/2]: " LANG_OPT
[[ -z "$LANG_OPT" ]] && LANG_OPT="1"

if [[ "$LANG_OPT" == "2" ]]; then
    LANG_CODE="es"
    MSG_INSTALL="[INFO] Instalando/actualizando RedAudit v2.5..."
    MSG_DONE="[OK] Instalación completada."
    MSG_USAGE="-> Ejecuta 'redaudit' para iniciar."
    MSG_ALIAS_ADDED="[INFO] Alias 'redaudit' añadido en"
    MSG_ALIAS_EXISTS="[INFO] Alias 'redaudit' ya existe en"
    MSG_PKGS="[OPTIONAL] Opcional: instalar utilidades recomendadas:"
    MSG_ASK="¿Instalar ahora? [S/n]: "
    MSG_APT_ERR="[ERROR] Error con apt."
else
    LANG_CODE="en"
    MSG_INSTALL="[INFO] Installing/updating RedAudit v2.5..."
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

EXTRA_PKGS="curl wget openssl nmap tcpdump tshark whois bind9-dnsutils python3-nmap python3-cryptography"

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
# 3) Install redaudit.py --> /usr/local/bin
# -------------------------------------------

SCRIPT_SRC="$(dirname "$0")/redaudit.py"

if [[ ! -f "$SCRIPT_SRC" ]]; then
    echo "❌ Error: redaudit.py not found next to installer!"
    echo "Place redaudit_install.sh and redaudit.py in the same directory."
    exit 1
fi

TEMP_SCRIPT=$(mktemp)
cp "$SCRIPT_SRC" "$TEMP_SCRIPT"

# Inject selected language
sed -i "s/^DEFAULT_LANG = .*/DEFAULT_LANG = \"$LANG_CODE\"/" "$TEMP_SCRIPT"

# Move into the system
mv "$TEMP_SCRIPT" /usr/local/bin/redaudit
chmod 755 /usr/local/bin/redaudit
chown root:root /usr/local/bin/redaudit

echo "✓ redaudit installed at /usr/local/bin/redaudit"

# -------------------------------------------
# 4) Alias setup
# -------------------------------------------

REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
USER_SHELL=$(getent passwd "$REAL_USER" | cut -d: -f7)

RC_FILE="$REAL_HOME/.bashrc"
[[ "$USER_SHELL" == *"zsh"* ]] && RC_FILE="$REAL_HOME/.zshrc"

if ! grep -q "alias redaudit=" "$RC_FILE" 2>/dev/null; then
    echo "alias redaudit='sudo /usr/local/bin/redaudit'" >> "$RC_FILE"
    chown "$REAL_USER" "$RC_FILE"
    echo "$MSG_ALIAS_ADDED $RC_FILE"
else
    echo "$MSG_ALIAS_EXISTS $RC_FILE"
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