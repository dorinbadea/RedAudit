#!/usr/bin/env python3
"""
RedAudit - Scanner Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

Network scanning, port enumeration, deep scan, and traffic capture functionality.
"""

import re
import os
import time
import subprocess
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional

from redaudit.utils.constants import (
    MAX_INPUT_LENGTH,
    TRAFFIC_CAPTURE_DEFAULT_DURATION,
    TRAFFIC_CAPTURE_MAX_DURATION,
    TRAFFIC_CAPTURE_PACKETS,
    WEB_SERVICES_KEYWORDS,
    WEB_SERVICES_EXACT,
    SUSPICIOUS_SERVICE_KEYWORDS,
)


def sanitize_ip(ip_str) -> Optional[str]:
    """
    Sanitize and validate IP address.

    Args:
        ip_str: Input IP address string

    Returns:
        Validated IP string or None if invalid
    """
    if ip_str is None:
        return None
    if not isinstance(ip_str, str):
        return None
    ip_str = ip_str.strip()
    if not ip_str:
        return None
    if len(ip_str) > MAX_INPUT_LENGTH:
        return None
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except (ValueError, TypeError):
        return None


def sanitize_hostname(hostname) -> Optional[str]:
    """
    Sanitize and validate hostname.

    Args:
        hostname: Input hostname string

    Returns:
        Validated hostname or None if invalid
    """
    if hostname is None:
        return None
    if not isinstance(hostname, str):
        return None
    hostname = hostname.strip()
    if not hostname:
        return None
    if len(hostname) > MAX_INPUT_LENGTH:
        return None
    if re.match(r"^[a-zA-Z0-9\.\-]+$", hostname):
        return hostname
    return None


def is_web_service(name: str) -> bool:
    """
    Check if a service name indicates a web service.

    Args:
        name: Service name from nmap

    Returns:
        True if service appears to be web-related
    """
    if not name:
        return False
    n = name.lower()
    if n in WEB_SERVICES_EXACT:
        return True
    return any(k in n for k in WEB_SERVICES_KEYWORDS)


def is_suspicious_service(name: str) -> bool:
    """
    Check if a service name indicates a suspicious/interesting service.

    Args:
        name: Service name from nmap

    Returns:
        True if service seems suspicious (VPN, proxy, etc.)
    """
    if not name:
        return False
    lname = name.lower()
    return any(k in lname for k in SUSPICIOUS_SERVICE_KEYWORDS)


def get_nmap_arguments(mode: str) -> str:
    """
    Get nmap arguments for the specified scan mode.

    Args:
        mode: Scan mode ('rapido', 'normal', 'completo')

    Returns:
        Nmap argument string
    """
    args = {
        "rapido": "-sn -T4 --max-retries 1 --host-timeout 10s",
        "normal": "-T4 -F -sV --version-intensity 5 --host-timeout 60s --open",
        "completo": "-T4 -p- -sV -sC -A --version-intensity 9 --host-timeout 300s --max-retries 2 --open",
    }
    return args.get(mode, args["normal"])


def extract_vendor_mac(text: str) -> tuple:
    """
    Extract MAC address and vendor from Nmap output.

    Args:
        text: Nmap output text

    Returns:
        Tuple of (mac_address, vendor) or (None, None)
    """
    if not text:
        return None, None
    # Standard Nmap MAC line: MAC Address: 00:11:22:33:44:55 (Vendor Name)
    match = re.search(r"MAC Address: ([0-9A-Fa-f:]+) \((.*?)\)", text)
    if match:
        return match.group(1), match.group(2)
    return None, None


def output_has_identity(records: List[Dict]) -> bool:
    """
    Check if scan records contain sufficient identity information (MAC/OS).

    Used to determine if Phase 2 of deep scan can be skipped.

    Args:
        records: List of scan command records

    Returns:
        True if MAC address, vendor, or OS detection info is found
    """
    for rec in records:
        stdout = rec.get("stdout", "") or ""
        stderr = rec.get("stderr", "") or ""
        combined = stdout + "\n" + stderr

        if not combined.strip():
            continue

        # Check for MAC address and vendor
        mac, vendor = extract_vendor_mac(combined)
        if mac or vendor:
            return True

        # Check for OS detection patterns
        os_patterns = [
            r"OS details?:",
            r"Running:\s*[A-Z]",
            r"OS CPE:",
            r"Aggressive OS guesses:",
            r"OS details:.*\(.*%\)",
            r"Device type:",
        ]

        for pattern in os_patterns:
            if re.search(pattern, combined, re.IGNORECASE | re.MULTILINE):
                return True

    return False


def run_nmap_command(
    cmd: List[str],
    timeout: int,
    host_ip: str,
    deep_obj: Dict,
    print_fn=None,
    t_fn=None
) -> Dict:
    """
    Run a single nmap command and collect output.

    Args:
        cmd: Command list
        timeout: Subprocess timeout
        host_ip: Target IP for logging
        deep_obj: Deep scan object to append command records
        print_fn: Optional print function
        t_fn: Optional translation function

    Returns:
        Command record dictionary
    """
    start = time.time()
    record = {"command": " ".join(cmd)}

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.time() - start
        record["returncode"] = res.returncode
        record["stdout"] = (res.stdout or "")[:8000]
        record["stderr"] = (res.stderr or "")[:2000]
        record["duration_seconds"] = round(duration, 2)
    except subprocess.TimeoutExpired as exc:
        duration = time.time() - start
        record["error"] = f"Timeout after {exc.timeout}s"
        record["duration_seconds"] = round(duration, 2)
    except Exception as exc:
        duration = time.time() - start
        record["error"] = str(exc)
        record["duration_seconds"] = round(duration, 2)

    deep_obj.setdefault("commands", []).append(record)
    return record


def capture_traffic_snippet(
    host_ip: str,
    output_dir: str,
    networks: List[Dict],
    extra_tools: Dict,
    duration: int = TRAFFIC_CAPTURE_DEFAULT_DURATION,
    logger=None
) -> Optional[Dict]:
    """
    Capture small PCAP snippet with tcpdump + optional tshark summary.

    Args:
        host_ip: Target IP
        output_dir: Directory for pcap files
        networks: Network info list
        extra_tools: Dict of available tool paths
        duration: Capture duration in seconds
        logger: Optional logger

    Returns:
        Capture info dictionary or None
    """
    if not extra_tools.get("tcpdump"):
        return None

    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return None

    if not isinstance(duration, (int, float)) or duration <= 0 or duration > TRAFFIC_CAPTURE_MAX_DURATION:
        if logger:
            logger.warning("Invalid capture duration %s, using default", duration)
        duration = TRAFFIC_CAPTURE_DEFAULT_DURATION

    # Find interface for the IP
    iface = None
    try:
        ip_obj = ipaddress.ip_address(safe_ip)
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["network"], strict=False)
                if ip_obj in net_obj:
                    iface = net.get("interface")
                    break
            except Exception:
                continue
    except ValueError:
        return None

    if not iface:
        if logger:
            logger.info("No interface found for host %s, skipping traffic capture", safe_ip)
        return None

    if not re.match(r"^[a-zA-Z0-9\-_]+$", iface):
        return None

    ts = datetime.now().strftime("%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    pcap_file = os.path.join(output_dir, f"traffic_{safe_ip.replace('.', '_')}_{ts}.pcap")

    cmd = [
        extra_tools["tcpdump"],
        "-i", iface,
        "host", safe_ip,
        "-c", str(TRAFFIC_CAPTURE_PACKETS),
        "-G", str(int(duration)),
        "-W", "1",
        "-w", pcap_file,
    ]

    info = {"pcap_file": pcap_file, "iface": iface}

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=duration + 5,
        )
    except subprocess.TimeoutExpired as exc:
        info["tcpdump_error"] = f"Timeout after {exc.timeout}s"
    except Exception as exc:
        info["tcpdump_error"] = str(exc)

    # Optional tshark summary
    if extra_tools.get("tshark"):
        try:
            res = subprocess.run(
                [extra_tools["tshark"], "-r", pcap_file, "-q", "-z", "io,phs"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            info["tshark_summary"] = (res.stdout or res.stderr or "")[:2000]
        except Exception as exc:
            info["tshark_error"] = str(exc)

    return info


def enrich_host_with_dns(host_record: Dict, extra_tools: Dict) -> None:
    """
    Enrich host record with DNS reverse lookup.

    Args:
        host_record: Host record dictionary
        extra_tools: Dict of available tool paths
    """
    ip_str = host_record["ip"]
    host_record.setdefault("dns", {})

    if extra_tools.get("dig"):
        try:
            res = subprocess.run(
                [extra_tools["dig"], "+short", "-x", ip_str],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.stdout.strip():
                host_record["dns"]["reverse"] = res.stdout.strip().splitlines()
        except Exception:
            pass


def enrich_host_with_whois(host_record: Dict, extra_tools: Dict) -> None:
    """
    Enrich host record with WHOIS data for public IPs.

    Args:
        host_record: Host record dictionary
        extra_tools: Dict of available tool paths
    """
    ip_str = host_record["ip"]
    host_record.setdefault("dns", {})

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if not ip_obj.is_private and extra_tools.get("whois"):
            res = subprocess.run(
                [extra_tools["whois"], ip_str],
                capture_output=True,
                text=True,
                timeout=15,
            )
            text = res.stdout or res.stderr
            if text:
                lines = [line for line in text.splitlines() if line.strip()][:25]
                host_record["dns"]["whois_summary"] = "\n".join(lines)
    except Exception:
        pass


def http_enrichment(url: str, extra_tools: Dict) -> Dict:
    """
    Enrich with HTTP headers using curl/wget.

    Args:
        url: Target URL
        extra_tools: Dict of available tool paths

    Returns:
        Dictionary with curl/wget headers
    """
    data = {}

    if extra_tools.get("curl"):
        try:
            res = subprocess.run(
                [extra_tools["curl"], "-I", "--max-time", "10", url],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if res.stdout:
                data["curl_headers"] = res.stdout.strip()[:2000]
        except Exception:
            pass

    if extra_tools.get("wget"):
        try:
            res = subprocess.run(
                [extra_tools["wget"], "--spider", "-S", "--timeout=10", url],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if res.stderr:
                data["wget_headers"] = res.stderr.strip()[:2000]
        except Exception:
            pass

    return data


def tls_enrichment(host_ip: str, port: int, extra_tools: Dict) -> Dict:
    """
    Enrich with TLS certificate information.

    Args:
        host_ip: Target IP
        port: Target port
        extra_tools: Dict of available tool paths

    Returns:
        Dictionary with TLS info
    """
    data = {}

    if extra_tools.get("openssl"):
        try:
            res = subprocess.run(
                [
                    extra_tools["openssl"], "s_client",
                    "-connect", f"{host_ip}:{port}",
                    "-servername", host_ip,
                    "-brief",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                input="",
            )
            if res.stdout:
                data["tls_info"] = res.stdout.strip()[:2000]
        except Exception:
            pass

    return data
