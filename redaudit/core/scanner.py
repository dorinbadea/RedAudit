#!/usr/bin/env python3
"""
RedAudit - Scanner Module
Copyright (C) 2025  Dorin Badea
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
    STATUS_UP,
    STATUS_DOWN,
    STATUS_FILTERED,
    STATUS_NO_RESPONSE,
    UDP_PRIORITY_PORTS,
)


def sanitize_ip(ip_str) -> Optional[str]:
    """
    Sanitize and validate IP address (supports both IPv4 and IPv6).

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


def is_ipv6(ip_str: str) -> bool:
    """
    Check if an IP address string is IPv6.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if IPv6, False if IPv4 or invalid
    """
    try:
        return ipaddress.ip_address(ip_str).version == 6
    except (ValueError, TypeError):
        return False


def is_ipv6_network(network_str: str) -> bool:
    """
    Check if a network CIDR string is IPv6.
    
    Args:
        network_str: Network CIDR string (e.g., '2001:db8::/32')
        
    Returns:
        True if IPv6 network, False otherwise
    """
    try:
        return ipaddress.ip_network(network_str, strict=False).version == 6
    except (ValueError, TypeError):
        return False


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


def is_port_anomaly(port: int, service_name: str) -> bool:
    """
    v3.2.2b: Detect anomalous services on standard ports.
    
    A standard port with an unexpected service may indicate a backdoor,
    hijacked service, or misconfiguration worth investigating.
    
    Args:
        port: Port number
        service_name: Service name detected by nmap
        
    Returns:
        True if service doesn't match expected for this port
    """
    from redaudit.utils.constants import STANDARD_PORT_SERVICES
    
    if not service_name or port not in STANDARD_PORT_SERVICES:
        return False
    
    expected = STANDARD_PORT_SERVICES.get(port, [])
    if not expected:
        return False
    
    svc_lower = service_name.lower()
    # Check if any expected keyword appears in the service name
    for exp in expected:
        if exp in svc_lower:
            return False
    
    # Service doesn't match any expected - anomaly!
    return True



def get_nmap_arguments(mode: str, config: Optional[Dict] = None) -> str:
    """
    Get nmap arguments for the specified scan mode.

    Args:
        mode: Scan mode ('rapido', 'normal', 'completo')
        config: Optional config dict with nmap_timing for stealth mode

    Returns:
        Nmap argument string
    """
    # v3.2.3: Support stealth mode with different timing templates
    timing = config.get("nmap_timing", "T4") if config else "T4"
    args = {
        "rapido": f"-sn -{timing} --max-retries 1 --host-timeout 10s",
        "normal": f"-{timing} -F -sV --version-intensity 5 --host-timeout 60s --open",
        # v2.9: Reduced max-retries from 2 to 1 for LAN efficiency
        "completo": f"-{timing} -p- -sV -sC -A --version-intensity 9 --host-timeout 300s --max-retries 1 --open",
    }
    return args.get(mode, args["normal"])


def get_nmap_arguments_for_target(mode: str, target: str) -> str:
    """
    Get nmap arguments for a specific target, adding -6 flag for IPv6.
    
    v3.0: Automatically detects if target is IPv6 and adds appropriate flags.

    Args:
        mode: Scan mode ('rapido', 'normal', 'completo')
        target: Target IP address or CIDR

    Returns:
        Nmap argument string with -6 flag if IPv6
    """
    base_args = get_nmap_arguments(mode)
    
    # Check if target is IPv6
    target_ip = target.split("/")[0] if "/" in target else target
    if is_ipv6(target_ip):
        return f"-6 {base_args}"
    
    return base_args


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


def extract_os_detection(text: str) -> Optional[str]:
    """
    Extract OS detection information from Nmap output.
    
    v3.1.4: New function to capture OS fingerprint data.

    Args:
        text: Nmap output text

    Returns:
        OS string or None if not detected
    """
    if not text:
        return None
    
    patterns = [
        r"OS details: (.+)",
        r"Running: (.+)",
        r"OS CPE: cpe:/o:([^\s]+)",
        r"Aggressive OS guesses: ([^,]+)",
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:100]
    
    return None


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

    # v3.1.4: Use relative path for portability, keep absolute for internal use
    pcap_filename = os.path.basename(pcap_file)
    info = {"pcap_file": pcap_filename, "pcap_file_abs": pcap_file, "iface": iface}

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


def exploit_lookup(service_name: str, version: str, extra_tools: Dict, logger=None) -> List[str]:
    """
    Query ExploitDB for known exploits matching service and version.

    Args:
        service_name: Service name (e.g., "Apache", "OpenSSH")
        version: Version string (e.g., "2.4.49", "7.9")
        extra_tools: Dict of available tool paths
        logger: Optional logger

    Returns:
        List of exploit descriptions (max 10)
    """
    if not extra_tools.get("searchsploit"):
        return []
    
    if not service_name or not version:
        return []
    
    # Sanitize inputs
    if not isinstance(service_name, str) or not isinstance(version, str):
        return []
    
    service_name = service_name.strip()[:50]
    version = version.strip()[:20]
    
    if not service_name or not version:
        return []
    
    # Build search query
    query = f"{service_name} {version}"
    
    try:
        res = subprocess.run(
            [extra_tools["searchsploit"], "--colour", "--nmap", query],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        if res.returncode != 0:
            return []
        
        output = res.stdout or ""
        if not output.strip():
            return []
        
        # Parse output - each exploit is on a line
        exploits = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("Exploit"):
                continue
            if "|" in line:  # Standard searchsploit format
                parts = line.split("|")
                if len(parts) >= 1:
                    exploit_title = parts[0].strip()
                    if exploit_title and len(exploit_title) > 10:
                        exploits.append(exploit_title[:150])
        
        # Return max 10 exploits
        return exploits[:10]
    
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("Searchsploit timeout for %s %s", service_name, version)
        return []
    except Exception as exc:
        if logger:
            logger.debug("Searchsploit error for %s %s: %s", service_name, version, exc)
        return []


def ssl_deep_analysis(host_ip: str, port: int, extra_tools: Dict, logger=None, timeout: int = 90) -> Optional[Dict]:
    """
    Perform comprehensive SSL/TLS security analysis using testssl.sh.
    
    v3.1.4: Increased default timeout to 90s and made it configurable.

    Args:
        host_ip: Target IP address
        port: Target port (typically 443)
        extra_tools: Dict of available tool paths
        logger: Optional logger
        timeout: Analysis timeout in seconds (default: 90)

    Returns:
        Dictionary with SSL/TLS analysis results or None
    """
    if not extra_tools.get("testssl.sh"):
        return None
    
    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return None
    
    if not isinstance(port, int) or port < 1 or port > 65535:
        return None
    
    try:
        # Run testssl.sh with JSON output if supported
        cmd = [
            extra_tools["testssl.sh"],
            "--quiet",
            "--fast",
            "--severity", "HIGH",
            f"{safe_ip}:{port}"
        ]
        
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        output = res.stdout or res.stderr or ""
        if not output.strip():
            return None
        
        # Parse output for key findings
        findings = {
            "target": f"{safe_ip}:{port}",
            "summary": "",
            "vulnerabilities": [],
            "weak_ciphers": [],
            "protocols": []
        }
        
        lines = output.splitlines()
        for line in lines:
            line_lower = line.lower()
            
            # Detect vulnerabilities
            if any(vuln in line_lower for vuln in ["vulnerable", "heartbleed", "poodle", "beast", "crime", "breach"]):
                if "not vulnerable" not in line_lower and "ok" not in line_lower:
                    findings["vulnerabilities"].append(line.strip()[:200])
            
            # Detect weak ciphers
            if "weak" in line_lower or "insecure" in line_lower:
                if "cipher" in line_lower or "encryption" in line_lower:
                    findings["weak_ciphers"].append(line.strip()[:150])
            
            # Detect protocols
            if any(proto in line_lower for proto in ["sslv2", "sslv3", "tls 1.0", "tls 1.1", "tls 1.2", "tls 1.3"]):
                findings["protocols"].append(line.strip()[:100])
        
        # Generate summary
        vuln_count = len(findings["vulnerabilities"])
        weak_count = len(findings["weak_ciphers"])
        
        if vuln_count > 0:
            findings["summary"] = f"CRITICAL: {vuln_count} vulnerabilities detected"
        elif weak_count > 0:
            findings["summary"] = f"WARNING: {weak_count} weak ciphers found"
        else:
            findings["summary"] = "No major issues detected"
        
        # Only return if we found something useful
        if vuln_count > 0 or weak_count > 0 or len(findings["protocols"]) > 0:
            # Truncate lists
            findings["vulnerabilities"] = findings["vulnerabilities"][:5]
            findings["weak_ciphers"] = findings["weak_ciphers"][:5]
            findings["protocols"] = findings["protocols"][:8]
            return findings
        
        return None
    
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("TestSSL timeout for %s:%d after %ds", safe_ip, port, timeout)
        return {"error": f"Analysis timeout after {timeout}s", "target": f"{safe_ip}:{port}"}
    except Exception as exc:
        if logger:
            logger.debug("TestSSL error for %s:%d: %s", safe_ip, port, exc)
        return None


def start_background_capture(
    host_ip: str,
    output_dir: str,
    networks: List[Dict],
    extra_tools: Dict,
    logger=None
) -> Optional[Dict]:
    """
    Start background traffic capture for concurrent scanning (v2.8.0).
    
    Returns capture info dict with 'process' key for the tcpdump subprocess,
    or None if capture couldn't be started.
    
    Args:
        host_ip: Target IP
        output_dir: Directory for pcap files
        networks: Network info list
        extra_tools: Dict of available tool paths
        logger: Optional logger
    
    Returns:
        Dict with 'process', 'pcap_file', 'pcap_file_abs', 'iface' or None
    """
    if not extra_tools.get("tcpdump"):
        return None

    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return None

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

    # v2.8.1: Limit capture to 200 packets for smaller PCAP files (~50-150KB)
    cmd = [
        extra_tools["tcpdump"],
        "-i", iface,
        "-c", "200",  # Capture max 200 packets
        "host", safe_ip,
        "-w", pcap_file,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # v3.1.4: Keep reports portable by storing relative filename; keep absolute for internal use.
        pcap_filename = os.path.basename(pcap_file)
        return {"process": proc, "pcap_file": pcap_filename, "pcap_file_abs": pcap_file, "iface": iface}
    except Exception as exc:
        if logger:
            logger.debug("Failed to start background capture for %s: %s", safe_ip, exc)
        return None


def stop_background_capture(
    capture_info: Dict,
    extra_tools: Dict,
    logger=None
) -> Optional[Dict]:
    """
    Stop background traffic capture and collect results (v2.8.0).
    
    Args:
        capture_info: Dict from start_background_capture with 'process', 'pcap_file', 'iface'
        extra_tools: Dict of available tool paths
        logger: Optional logger
    
    Returns:
        PCAP info dict with tshark summary, or None
    """
    if not capture_info or "process" not in capture_info:
        return None
    
    proc = capture_info["process"]
    pcap_file_abs = capture_info.get("pcap_file_abs") or capture_info.get("pcap_file", "")
    iface = capture_info.get("iface", "")
    
    pcap_file = capture_info.get("pcap_file")
    if not pcap_file:
        pcap_file = os.path.basename(pcap_file_abs) if pcap_file_abs else ""
    # If older capture_info stored an absolute path in pcap_file, normalize to portable filename.
    if pcap_file and ("/" in pcap_file or "\\" in pcap_file):
        pcap_file = os.path.basename(pcap_file)

    result = {"pcap_file": pcap_file, "pcap_file_abs": pcap_file_abs, "iface": iface}
    
    # Terminate the capture process
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        result["tcpdump_error"] = "Process killed after timeout"
    except Exception as exc:
        result["tcpdump_error"] = str(exc)
    
    # Generate tshark summary if available
    if pcap_file_abs and os.path.exists(pcap_file_abs):
        # Ensure PCAP is stored with secure permissions (best-effort).
        try:
            os.chmod(pcap_file_abs, 0o600)
        except Exception:
            pass

    if extra_tools.get("tshark") and pcap_file_abs and os.path.exists(pcap_file_abs):
        try:
            res = subprocess.run(
                [extra_tools["tshark"], "-r", pcap_file_abs, "-q", "-z", "io,phs"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            summary = (res.stdout or res.stderr or "")[:2000]
            if summary.strip():
                result["tshark_summary"] = summary
        except Exception as exc:
            result["tshark_error"] = str(exc)
    
    return result


def banner_grab_fallback(
    host_ip: str,
    ports: List[int],
    extra_tools: Dict = None,
    timeout: int = 30,
    logger=None
) -> Dict[int, Dict]:
    """
    Fallback banner grabbing for unidentified services (v2.8.0).
    
    Uses nmap --script banner,ssl-cert for additional service info.
    
    Args:
        host_ip: Target IP
        ports: List of port numbers to scan (max 20)
        extra_tools: Dict of available tool paths (unused, kept for consistency)
        timeout: Subprocess timeout
        logger: Optional logger
    
    Returns:
        Dict mapping port -> {"banner": str, "ssl_cert": str}
    """
    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return {}
    
    if not ports:
        return {}
    
    # Limit to 20 ports max
    ports = [p for p in ports if isinstance(p, int) and 1 <= p <= 65535][:20]
    if not ports:
        return {}
    
    port_str = ",".join(str(p) for p in ports)
    
    cmd = [
        "nmap", "-sV", "--script", "banner,ssl-cert",
        "-p", port_str,
        "-Pn",
        "--host-timeout", "60s",
        safe_ip
    ]
    
    results: Dict[int, Dict] = {}
    
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        output = res.stdout or ""
        
        # Parse output for port info
        current_port = None
        for line in output.splitlines():
            # Match port lines like "80/tcp open http"
            port_match = re.match(r"(\d+)/tcp\s+\w+\s+(\S+)", line)
            if port_match:
                current_port = int(port_match.group(1))
                results.setdefault(current_port, {})
                results[current_port]["service"] = port_match.group(2)
            
            # Match banner lines
            if current_port and "banner:" in line.lower():
                banner = line.split(":", 1)[-1].strip()
                results[current_port]["banner"] = banner[:500]
            
            # Match SSL cert info
            if current_port and "ssl-cert:" in line.lower():
                results.setdefault(current_port, {})["ssl_cert"] = line.strip()[:500]
                
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("Banner grab timeout for %s ports %s", safe_ip, port_str)
    except Exception as exc:
        if logger:
            logger.debug("Banner grab error for %s: %s", safe_ip, exc)
    
    return results


def finalize_host_status(host_record: Dict) -> str:
    """
    Determine the final host status based on all available data (v2.8.0).
    
    Improves accuracy by considering deep scan results, not just initial ping response.
    
    Args:
        host_record: Host record dictionary
    
    Returns:
        Final status string (STATUS_UP, STATUS_FILTERED, STATUS_NO_RESPONSE, STATUS_DOWN)
    """
    current_status = host_record.get("status", STATUS_DOWN)
    
    # If already up, keep it
    if current_status == STATUS_UP:
        return STATUS_UP
    
    # Check if we have meaningful data from deep scan
    deep_scan = host_record.get("deep_scan", {})
    if not deep_scan:
        return current_status
    
    # Check for MAC/vendor (definite proof of host presence)
    if deep_scan.get("mac_address") or deep_scan.get("vendor"):
        return STATUS_FILTERED  # Host exists but filtered initial probes
    
    # Check command outputs for any response indicators
    commands = deep_scan.get("commands", [])
    for cmd_record in commands:
        stdout = cmd_record.get("stdout", "") or ""
        
        # Host responded in some way
        if "Host is up" in stdout:
            return STATUS_FILTERED
        
        # Found open ports
        if re.search(r"\d+/tcp\s+open", stdout):
            return STATUS_UP
        
        # OS detected
        if "OS details:" in stdout or "Running:" in stdout:
            return STATUS_FILTERED
    
    # Check for ports found
    if host_record.get("ports") and len(host_record.get("ports", [])) > 0:
        return STATUS_UP
    
    # No meaningful response at all
    if current_status in ("down", STATUS_DOWN):
        # But we tried deep scan, so it's at least no-response rather than definitively down
        if commands:
            return STATUS_NO_RESPONSE
    
    return current_status
