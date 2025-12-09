#!/usr/bin/env python3
"""
RedAudit - Constants and Configuration
Copyright (C) 2026  Dorin Badea
GPLv3 License
"""

# Version
VERSION = "2.7.0"

# Default language (installer may override)
DEFAULT_LANG = "en"

# Security constants
MAX_INPUT_LENGTH = 1024  # Maximum length for IP/hostname inputs
MAX_CIDR_LENGTH = 50     # Maximum length for CIDR ranges
MAX_SUBPROCESS_RETRIES = 2  # Maximum retries for subprocess calls

# Scan timeouts (seconds)
DEEP_SCAN_TIMEOUT = 400
TRAFFIC_CAPTURE_DEFAULT_DURATION = 15
TRAFFIC_CAPTURE_MAX_DURATION = 120
TRAFFIC_CAPTURE_PACKETS = 50

# Heartbeat thresholds (seconds)
HEARTBEAT_INTERVAL = 30
HEARTBEAT_WARN_THRESHOLD = 60
HEARTBEAT_FAIL_THRESHOLD = 300

# Encryption parameters
PBKDF2_ITERATIONS = 480000
SALT_SIZE = 16
MIN_PASSWORD_LENGTH = 12

# Report defaults
DEFAULT_OUTPUT_DIR = "~/RedAuditReports"
DEFAULT_THREADS = 6
MAX_THREADS = 16
MIN_THREADS = 1
MAX_PORTS_DISPLAY = 50

# File permissions
SECURE_FILE_MODE = 0o600

# Service detection keywords
WEB_SERVICES_KEYWORDS = [
    "http", "https", "ssl", "www", "web", "admin", "proxy", "alt", "connect"
]

WEB_SERVICES_EXACT = [
    "http", "https", "www", "http-proxy", "ssl/http",
    "ssl/https", "http-alt", "http-admin", "http-connect"
]

SUSPICIOUS_SERVICE_KEYWORDS = [
    "socks", "socks5", "nagios", "nsca", "proxy", "vpn", "tor", "tcpwrapped"
]

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
