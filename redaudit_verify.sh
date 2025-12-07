#!/bin/bash
# RedAudit - Interactive Network Auditor
# Copyright (C) 2025  Dorin Badea
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# RedAudit Installation Verification Script

echo "🔍 RedAudit v2.5 Installation Verification"
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