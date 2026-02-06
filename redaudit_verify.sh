#!/bin/bash
# RedAudit - Interactive Network Auditor
# Copyright (C) 2026  Dorin Badea
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

echo "RedAudit v3.3.0 Installation Verification"
echo "========================================"
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
check_cmd searchsploit
check_cmd testssl.sh
if ! command -v testssl.sh &>/dev/null; then
    echo "   -> Required for TLS deep checks (full mode). Run: sudo bash redaudit_install.sh"
fi
check_cmd proxychains4

echo
echo "Network Discovery tools (v3.2+):"
echo "-----------------------------------"
check_cmd nbtscan
check_cmd netdiscover
check_cmd fping
check_cmd avahi-browse
check_cmd arp-scan
check_cmd lldpctl

echo
echo "Red Team tools (v3.2+):"
echo "------------------------"
check_cmd snmpwalk
check_cmd enum4linux
check_cmd smbclient
check_cmd masscan
check_cmd rpcclient  # Part of smbclient package
check_cmd ldapsearch
check_cmd bettercap
check_cmd kerbrute

echo
echo "Python modules (optional):"
echo "--------------------------"
if python3 -c "import scapy" 2>/dev/null; then
    echo "✅ python3-scapy"
else
    echo "❌ python3-scapy (optional, for passive 802.1Q sniffing)"
fi

echo
echo "========================================"
echo "Verification complete!"
