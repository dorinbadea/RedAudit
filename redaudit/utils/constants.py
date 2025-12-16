#!/usr/bin/env python3
"""
RedAudit - Constants and Configuration
Copyright (C) 2025  Dorin Badea
GPLv3 License
"""

# Version
VERSION = "3.2.3"
SCHEMA_VERSION = "3.2"  # Report schema version (may differ from app version)

# Default language (installer may override)
DEFAULT_LANG = "en"

# Security constants
MAX_INPUT_LENGTH = 1024  # Maximum length for IP/hostname inputs
MAX_CIDR_LENGTH = 50  # Maximum length for CIDR ranges
MAX_SUBPROCESS_RETRIES = 2  # Maximum retries for subprocess calls

# Host status constants (v2.8.0)
STATUS_UP = "up"
STATUS_DOWN = "down"
STATUS_FILTERED = "filtered"
STATUS_NO_RESPONSE = "no-response"

# Scan timeouts (seconds)
DEEP_SCAN_TIMEOUT = 400
DEEP_SCAN_TIMEOUT_EXTENDED = 600  # For full UDP scans
UDP_QUICK_TIMEOUT = 120  # For priority UDP ports only
TRAFFIC_CAPTURE_DEFAULT_DURATION = 15
TRAFFIC_CAPTURE_MAX_DURATION = 120
TRAFFIC_CAPTURE_PACKETS = 50

# UDP scanning configuration (v2.9)
UDP_PRIORITY_PORTS = "53,67,68,69,123,137,138,139,161,162,445,500,514,520,1900,4500,5353"
UDP_SCAN_MODE_QUICK = "quick"
UDP_SCAN_MODE_FULL = "full"
DEFAULT_UDP_MODE = UDP_SCAN_MODE_QUICK

# v2.9: Optimized UDP scanning for LAN
UDP_TOP_PORTS = 100  # Default UDP port count for full scans (vs 65535)
UDP_HOST_TIMEOUT_STRICT = "300s"  # 5 minutes max per host
UDP_MAX_RETRIES_LAN = 1  # Single retry for LAN environments

# Heartbeat thresholds (seconds)
HEARTBEAT_INTERVAL = 30
HEARTBEAT_WARN_THRESHOLD = 60
HEARTBEAT_FAIL_THRESHOLD = 300

# Encryption parameters
PBKDF2_ITERATIONS = 480000
SALT_SIZE = 16
MIN_PASSWORD_LENGTH = 12

# Report defaults
DEFAULT_OUTPUT_DIR = "~/Documents/RedAuditReports"
DEFAULT_THREADS = 6
MAX_THREADS = 16
MIN_THREADS = 1
MAX_PORTS_DISPLAY = 50

# File permissions
SECURE_FILE_MODE = 0o600

# Service detection keywords
WEB_SERVICES_KEYWORDS = ["http", "https", "ssl", "www", "web", "admin", "proxy", "alt", "connect"]

WEB_SERVICES_EXACT = [
    "http",
    "https",
    "www",
    "http-proxy",
    "ssl/http",
    "ssl/https",
    "http-alt",
    "http-admin",
    "http-connect",
]

SUSPICIOUS_SERVICE_KEYWORDS = [
    # Original suspicious services
    "socks",
    "socks5",
    "nagios",
    "nsca",
    "proxy",
    "vpn",
    "tor",
    "tcpwrapped",
    # v3.2.2b: Backdoor/unusual indicators
    "unknown",
    "backdoor",
    "rootkit",
    "shell",
    "reverse",
    "bindshell",
    "netcat",
    "ncat",
    "metasploit",
    "meterpreter",
    "c2",
    "rat",
    "cobalt",
    "empire",
    "beacon",
]

# v3.2.2b: Well-known ports that should NOT have unexpected services
# If a service appears on standard port but doesn't match expected, flag it
STANDARD_PORT_SERVICES = {
    21: ["ftp"],
    22: ["ssh", "openssh"],
    23: ["telnet"],
    25: ["smtp", "mail"],
    53: ["domain", "dns"],
    80: ["http", "www"],
    110: ["pop3"],
    143: ["imap"],
    443: ["https", "ssl"],
    445: ["microsoft-ds", "smb"],
    3306: ["mysql"],
    3389: ["ms-wbt-server", "rdp"],
    5432: ["postgresql"],
    5900: ["vnc"],
    8080: ["http-proxy", "http"],
}


# Console colors
COLORS = {
    "HEADER": "\033[95m",
    "OKBLUE": "\033[94m",
    "OKGREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m",
    "CYAN": "\033[96m",
}
