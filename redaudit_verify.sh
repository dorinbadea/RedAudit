#!/bin/bash
# RedAudit Installation Verification Script

echo "🔍 RedAudit Installation Verification"
echo "======================================"
echo

# Check binary
if [ -x "/usr/local/bin/redaudit" ]; then
    echo "✅ RedAudit binary found at /usr/local/bin/redaudit"
else
    echo "❌ RedAudit binary not found or not executable"
    exit 1
fi

# Check alias in current shell
if alias redaudit 2>/dev/null | grep -q "sudo /usr/local/bin/redaudit"; then
    echo "✅ Alias 'redaudit' configured correctly in current shell"
else
    echo "⚠️  Alias 'redaudit' not detected in this shell"
    echo "   Try: source ~/.bashrc  or  source ~/.zshrc"
fi

echo
echo "Checking dependencies:"
echo "----------------------"

check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo "✅ $1"
    else
        echo "❌ $1 (missing)"
    fi
}

check_cmd nmap
check_cmd python3

echo
echo "Python modules:"
echo "---------------"

if python3 -c "import nmap" 2>/dev/null; then
    echo "✅ python3-nmap"
else
    echo "❌ python3-nmap (missing)"
fi

if python3 -c "from cryptography.fernet import Fernet" 2>/dev/null; then
    echo "✅ python3-cryptography"
else
    echo "❌ python3-cryptography (missing)"
fi

echo
echo "Optional tools:"
echo "---------------"
check_cmd whatweb
check_cmd nikto
check_cmd tcpdump
check_cmd tshark
check_cmd curl
check_cmd wget
check_cmd openssl
check_cmd whois
check_cmd dig

echo
echo "======================================"
echo "Verification complete!"