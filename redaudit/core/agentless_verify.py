#!/usr/bin/env python3
"""
RedAudit - Agentless Verification (SMB/RDP/LDAP/SSH/HTTP)

Goal:
- Add high-signal, low-risk enrichment for heterogeneous networks without installing agents on targets.
- Use best-effort nmap scripts to extract identity and posture hints per protocol.

This is intentionally opt-in, because it adds additional network probes.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.utils.dry_run import is_dry_run
from redaudit.core.scanner import is_web_service, sanitize_ip
from redaudit.core.models import Host


_REDAUDIT_REDACT_ENV_KEYS = {"NVD_API_KEY", "GITHUB_TOKEN"}


@dataclass(frozen=True)
class AgentlessProbeTarget:
    ip: str
    smb: bool = False
    rdp: bool = False
    ldap: bool = False
    ssh_ports: Tuple[int, ...] = ()
    http_ports: Tuple[int, ...] = ()


_HTTP_PORT_HINTS = {80, 81, 443, 8000, 8080, 8443, 8888, 9443}


def _parse_service_name(port: Dict[str, Any]) -> str:
    return str(port.get("service") or port.get("name") or "").strip()


def select_agentless_probe_targets(
    host_results: Sequence[Dict[str, Any]],
) -> List[AgentlessProbeTarget]:
    targets: List[AgentlessProbeTarget] = []
    for host in host_results or []:
        open_ports: set[int] = set()
        ssh_ports: set[int] = set()
        http_ports: set[int] = set()

        # 1. Extract IP and standardized port/service tuples
        # Format: (port_num, service_name)
        extracted_ports: List[Tuple[int, str]] = []
        host_ip = ""

        if isinstance(host, Host):
            host_ip = host.ip
            for svc in host.services:
                try:
                    p_num = int(svc.port)
                    s_name = (svc.name or "").lower()
                    extracted_ports.append((p_num, s_name))
                except (ValueError, TypeError):
                    continue
        else:
            host_ip = sanitize_ip(host.get("ip"))
            for p_dict in host.get("ports") or []:
                try:
                    p_num = int(p_dict.get("port"))
                    s_name = _parse_service_name(p_dict).lower()
                    extracted_ports.append((p_num, s_name))
                except (ValueError, TypeError):
                    continue

        if not host_ip:
            continue

        # 2. Analyze ports
        for port_num, service in extracted_ports:
            open_ports.add(port_num)

            if service and "ssh" in service:
                ssh_ports.add(port_num)
            if is_web_service(service):
                http_ports.add(port_num)
            if port_num in _HTTP_PORT_HINTS:
                http_ports.add(port_num)

        smb = 445 in open_ports
        rdp = 3389 in open_ports
        ldap = bool(open_ports.intersection({389, 636}))
        if 22 in open_ports:
            ssh_ports.add(22)

        if ssh_ports or http_ports or smb or rdp or ldap:
            targets.append(
                AgentlessProbeTarget(
                    ip=host_ip,
                    smb=smb,
                    rdp=rdp,
                    ldap=ldap,
                    ssh_ports=tuple(sorted(ssh_ports)[:3]),
                    http_ports=tuple(sorted(http_ports)[:5]),
                )
            )
    return targets


def _make_runner(
    *,
    logger=None,
    dry_run: Optional[bool] = None,
    timeout: float = 45.0,
    command_wrapper=None,
) -> CommandRunner:
    return CommandRunner(
        logger=logger,
        dry_run=is_dry_run(dry_run),
        default_timeout=float(timeout),
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys=_REDAUDIT_REDACT_ENV_KEYS,
        command_wrapper=command_wrapper,
    )


def _decode_text(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _run_nmap_script(
    ip: str,
    *,
    ports: str,
    scripts: str,
    logger=None,
    dry_run: Optional[bool] = None,
    proxy_manager=None,
    timeout_s: float = 60.0,
) -> Tuple[int, str, str]:
    if not shutil.which("nmap"):
        return 127, "", "nmap not found"
    runner = _make_runner(
        logger=logger,
        dry_run=dry_run,
        timeout=timeout_s,
        command_wrapper=get_proxy_command_wrapper(proxy_manager),
    )
    cmd = [
        "nmap",
        "-Pn",
        "-n",
        "-p",
        ports,
        "--script",
        scripts,
        "--host-timeout",
        f"{int(timeout_s)}s",
        ip,
    ]
    res = runner.run(cmd, capture_output=True, text=True, check=False, timeout=float(timeout_s))
    return int(res.returncode), _decode_text(res.stdout), _decode_text(res.stderr)


def parse_smb_nmap(text: str) -> Dict[str, Any]:
    """
    Parse best-effort SMB/NTLM-ish details from nmap script output.
    """
    out: Dict[str, Any] = {}
    t = text or ""

    def _grab(pattern: str, key: str, *, flags=0) -> None:
        m = re.search(pattern, t, flags)
        if m:
            out[key] = (m.group(1) or "").strip()

    _grab(r"OS:\s*(.+)", "os", flags=re.IGNORECASE)
    _grab(r"Computer name:\s*(.+)", "computer_name", flags=re.IGNORECASE)
    _grab(r"NetBIOS computer name:\s*(.+)", "netbios_name", flags=re.IGNORECASE)
    _grab(r"Domain name:\s*(.+)", "domain", flags=re.IGNORECASE)
    _grab(r"Workgroup:\s*(.+)", "workgroup", flags=re.IGNORECASE)

    # SMB signing posture (common phrasing from smb2-security-mode)
    signing_required = None
    signing_enabled = None
    if re.search(r"message signing enabled but not required", t, re.IGNORECASE):
        signing_enabled = True
        signing_required = False
    elif re.search(r"message signing enabled and required", t, re.IGNORECASE):
        signing_enabled = True
        signing_required = True
    elif re.search(r"message signing disabled", t, re.IGNORECASE):
        signing_enabled = False
        signing_required = False
    if signing_enabled is not None:
        out["smb_signing_enabled"] = signing_enabled
    if signing_required is not None:
        out["smb_signing_required"] = signing_required

    # SMBv1 presence (best-effort from smb-protocols)
    if re.search(r"SMBv1", t, re.IGNORECASE):
        out["smbv1_detected"] = True

    return out


def parse_ldap_rootdse(text: str) -> Dict[str, Any]:
    """
    Parse key RootDSE attributes from ldap-rootdse output (nmap or ldapsearch-like).
    """
    parsed: Dict[str, Any] = {}
    if not text:
        return parsed

    # Nmap scripts often output "key: value" lines.
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if not key or not val:
            continue
        if key in (
            "defaultNamingContext",
            "rootDomainNamingContext",
            "dnsHostName",
            "ldapServiceName",
            "domainFunctionality",
            "forestFunctionality",
        ):
            parsed[key] = val
        elif key == "supportedLDAPVersion":
            versions = [v.strip() for v in re.split(r"[,\s]+", val) if v.strip()]
            parsed["supportedLDAPVersion"] = versions[:10]

    return parsed


def parse_rdp_ntlm_info(text: str) -> Dict[str, Any]:
    """
    Parse rdp-ntlm-info output from nmap to extract host/domain hints.
    """
    out: Dict[str, Any] = {}
    t = text or ""

    def _grab(pattern: str, key: str) -> None:
        m = re.search(pattern, t, re.IGNORECASE)
        if m:
            out[key] = (m.group(1) or "").strip()

    _grab(r"NetBIOS_Computer_Name:\s*(.+)", "netbios_name")
    _grab(r"NetBIOS_Domain_Name:\s*(.+)", "netbios_domain")
    _grab(r"DNS_Computer_Name:\s*(.+)", "dns_computer_name")
    _grab(r"DNS_Domain_Name:\s*(.+)", "dns_domain_name")
    _grab(r"Product_Version:\s*(.+)", "product_version")

    return out


def parse_ssh_hostkeys(text: str) -> Dict[str, Any]:
    """
    Parse ssh-hostkey output for fingerprint hints.
    """
    out: Dict[str, Any] = {}
    if not text:
        return out
    hostkeys: List[str] = []
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line or "SHA256:" not in line and "MD5:" not in line:
            continue
        line = re.sub(r"^\|[_\s]*", "", line)
        hostkeys.append(line[:256])
        if len(hostkeys) >= 5:
            break
    if hostkeys:
        out["hostkeys"] = hostkeys
    return out


def parse_http_probe(text: str) -> Dict[str, Any]:
    """
    Parse http-title and http-server-header outputs for identity hints.
    Also attempts to fingerprint device vendor/model from common patterns.
    """
    out: Dict[str, Any] = {}
    if not text:
        return out

    lines = [line for line in str(text).splitlines() if line.strip()]
    cleaned = [re.sub(r"^\|[_\s]*", "", line).strip() for line in lines]
    for idx, line in enumerate(cleaned):
        lower = line.lower()
        if lower.startswith("http-title:"):
            title = line.split(":", 1)[1].strip()
            if title:
                out["title"] = title[:256]
        elif lower.startswith("http-server-header:"):
            server = line.split(":", 1)[1].strip()
            if not server and idx + 1 < len(cleaned):
                server = cleaned[idx + 1].strip()
            if server:
                out["server"] = server[:256]

    # v3.8.8: Device fingerprinting from HTTP title/server
    device_info = _fingerprint_device_from_http(out.get("title", ""), out.get("server", ""))
    out.update(device_info)

    return out


# Device fingerprinting patterns from HTTP title/server headers
# Each pattern: (compiled_regex, vendor, device_type, model_group_index or None)
_HTTP_DEVICE_PATTERNS = [
    # Router vendors
    (re.compile(r"(Vodafone[- ]?[A-Z0-9\-]+)", re.I), "Vodafone", "router", 1),
    (re.compile(r"(FRITZ!?[Bb]ox[- ]?\d*)", re.I), "AVM", "router", 1),
    (re.compile(r"(FRITZ!?Repeater[- ]?[A-Z0-9\-]*)", re.I), "AVM", "router", 1),
    (re.compile(r"(TP-?LINK[- ][A-Z0-9\-]+)", re.I), "TP-Link", "router", 1),
    (re.compile(r"(NETGEAR[- ]?[A-Z0-9\-]*)", re.I), "NETGEAR", "router", 1),
    (re.compile(r"(ASUS[- ]?RT[- ]?[A-Z0-9\-]+)", re.I), "ASUS", "router", 1),
    (re.compile(r"(Linksys[- ]?[A-Z0-9\-]*)", re.I), "Linksys", "router", 1),
    (re.compile(r"(D-?Link[- ]?[A-Z0-9\-]*)", re.I), "D-Link", "router", 1),
    (re.compile(r"(Ubiquiti|UniFi|EdgeRouter)", re.I), "Ubiquiti", "router", 1),
    (re.compile(r"(MikroTik|RouterOS)", re.I), "MikroTik", "router", 1),
    (re.compile(r"(pfSense|OPNsense)", re.I), "Netgate", "router", 1),
    (re.compile(r"(OpenWrt|LEDE)", re.I), "OpenWrt", "router", 1),
    (re.compile(r"(Huawei[- ]?[A-Z0-9\-]*)", re.I), "Huawei", "router", 1),
    (re.compile(r"(ZTE[- ]?[A-Z0-9\-]*)", re.I), "ZTE", "router", 1),
    (re.compile(r"(Vigor[- ]?\d+|DrayTek)", re.I), "DrayTek", "router", 1),
    (re.compile(r"(Synology)", re.I), "Synology", "nas", 1),
    (re.compile(r"(QNAP)", re.I), "QNAP", "nas", 1),
    # Switches
    (re.compile(r"(Cisco[- ]?[A-Z0-9\-]*)", re.I), "Cisco", "switch", 1),
    (re.compile(r"(HP[- ]?ProCurve|Aruba|HPE)", re.I), "HPE/Aruba", "switch", 1),
    (re.compile(r"(Juniper[- ]?[A-Z0-9\-]*)", re.I), "Juniper", "switch", 1),
    # Cameras
    (re.compile(r"(Hikvision[- ]?[A-Z0-9\-]*)", re.I), "Hikvision", "camera", 1),
    (re.compile(r"(Dahua[- ]?[A-Z0-9\-]*)", re.I), "Dahua", "camera", 1),
    (re.compile(r"(Axis[- ]?[A-Z0-9\-]*|VAPIX)", re.I), "Axis", "camera", 1),
    (re.compile(r"(Reolink[- ]?[A-Z0-9\-]*)", re.I), "Reolink", "camera", 1),
    (re.compile(r"(ONVIF)", re.I), "ONVIF", "camera", None),
    # IoT / Smart Home
    (re.compile(r"(Philips Hue|Hue Bridge)", re.I), "Philips", "iot", 1),
    (re.compile(r"(Home Assistant)", re.I), "Home Assistant", "iot", 1),
    (re.compile(r"(Tasmota)", re.I), "Tasmota", "iot", 1),
    (re.compile(r"(Shelly[- ]?[A-Z0-9\-]*)", re.I), "Shelly", "iot", 1),
    (re.compile(r"(Sonoff[- ]?[A-Z0-9\-]*)", re.I), "Sonoff", "iot", 1),
    # Printers
    (
        re.compile(r"(HP[- ]?(LaserJet|OfficeJet|DeskJet)[- ]?[A-Z0-9\-]*)", re.I),
        "HP",
        "printer",
        1,
    ),
    (re.compile(r"(EPSON[- ]?[A-Z0-9\-]*)", re.I), "Epson", "printer", 1),
    (re.compile(r"(Brother[- ]?[A-Z0-9\-]*)", re.I), "Brother", "printer", 1),
    (re.compile(r"(Canon[- ]?(PIXMA|imageCLASS)[- ]?[A-Z0-9\-]*)", re.I), "Canon", "printer", 1),
    # Generic server software (fallback for type detection)
    (re.compile(r"(Apache|nginx|IIS|lighttpd)", re.I), None, "server", 1),
    (re.compile(r"(ESXi|vSphere|VMware)", re.I), "VMware", "hypervisor", 1),
    (re.compile(r"(Proxmox)", re.I), "Proxmox", "hypervisor", 1),
    (re.compile(r"(iLO|iDRAC|IPMI)", re.I), None, "bmc", 1),
]


def _fingerprint_device_from_http(title: str, server: str) -> Dict[str, Any]:
    """
    Attempt to identify device vendor, model, and type from HTTP title/server.
    Returns dict with 'device_vendor', 'device_model', 'device_type' if matched.
    """
    result: Dict[str, Any] = {}
    combined = f"{title} {server}"

    for pattern, vendor, device_type, model_group in _HTTP_DEVICE_PATTERNS:
        match = pattern.search(combined)
        if match:
            if vendor:
                result["device_vendor"] = vendor
            result["device_type"] = device_type
            if model_group is not None:
                model = match.group(model_group).strip()
                if model and len(model) > 2:
                    result["device_model"] = model[:64]
            break  # Stop at first match (most specific)

    return result


def probe_agentless_services(
    target: AgentlessProbeTarget,
    *,
    logger=None,
    dry_run: Optional[bool] = None,
    proxy_manager=None,
) -> Dict[str, Any]:
    """
    Run best-effort agentless probes for SMB/RDP/LDAP/SSH/HTTP on a host.
    """
    ip = sanitize_ip(target.ip)
    if not ip:
        return {"ip": target.ip, "error": "invalid_ip"}
    if not shutil.which("nmap"):
        return {"ip": ip, "error": "tool_missing", "tool": "nmap"}

    result: Dict[str, Any] = {
        "ip": ip,
        "smb": None,
        "rdp": None,
        "ldap": None,
        "ssh": None,
        "http": None,
    }

    if target.smb:
        rc, out, err = _run_nmap_script(
            ip,
            ports="445",
            scripts="smb-os-discovery,smb2-security-mode,smb-protocols",
            logger=logger,
            dry_run=dry_run,
            proxy_manager=proxy_manager,
            timeout_s=60.0,
        )
        parsed = parse_smb_nmap(out + "\n" + err)
        parsed["returncode"] = rc
        result["smb"] = parsed

    if target.rdp:
        rc, out, err = _run_nmap_script(
            ip,
            ports="3389",
            scripts="rdp-ntlm-info",
            logger=logger,
            dry_run=dry_run,
            proxy_manager=proxy_manager,
            timeout_s=60.0,
        )
        parsed = parse_rdp_ntlm_info(out + "\n" + err)
        parsed["returncode"] = rc
        result["rdp"] = parsed

    if target.ldap:
        rc, out, err = _run_nmap_script(
            ip,
            ports="389,636",
            scripts="ldap-rootdse",
            logger=logger,
            dry_run=dry_run,
            proxy_manager=proxy_manager,
            timeout_s=60.0,
        )
        parsed = parse_ldap_rootdse(out + "\n" + err)
        parsed["returncode"] = rc
        result["ldap"] = parsed

    if target.ssh_ports:
        ssh_ports = ",".join(str(p) for p in target.ssh_ports)
        rc, out, err = _run_nmap_script(
            ip,
            ports=ssh_ports,
            scripts="ssh-hostkey",
            logger=logger,
            dry_run=dry_run,
            proxy_manager=proxy_manager,
            timeout_s=45.0,
        )
        parsed = parse_ssh_hostkeys(out + "\n" + err)
        parsed["returncode"] = rc
        parsed["ports"] = list(target.ssh_ports)
        result["ssh"] = parsed

    if target.http_ports:
        http_ports = ",".join(str(p) for p in target.http_ports)
        rc, out, err = _run_nmap_script(
            ip,
            ports=http_ports,
            scripts="http-title,http-server-header",
            logger=logger,
            dry_run=dry_run,
            proxy_manager=proxy_manager,
            timeout_s=45.0,
        )
        parsed = parse_http_probe(out + "\n" + err)
        parsed["returncode"] = rc
        parsed["ports"] = list(target.http_ports)
        result["http"] = parsed

    return result


def summarize_agentless_fingerprint(probe_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize probe results into a compact fingerprint for entity resolution and reports.
    """
    fp: Dict[str, Any] = {"ip": probe_result.get("ip")}

    smb = probe_result.get("smb") or {}
    rdp = probe_result.get("rdp") or {}
    ldap = probe_result.get("ldap") or {}
    ssh = probe_result.get("ssh") or {}
    http = probe_result.get("http") or {}

    # Prefer RDP-derived naming (often richer), fallback to SMB.
    domain = (
        rdp.get("dns_domain_name")
        or rdp.get("netbios_domain")
        or smb.get("domain")
        or ldap.get("defaultNamingContext")
    )
    name = rdp.get("dns_computer_name") or rdp.get("netbios_name") or smb.get("computer_name")

    if domain:
        fp["domain"] = str(domain)[:256]
    if name:
        fp["computer_name"] = str(name)[:256]

    for k in ("product_version",):
        if rdp.get(k):
            fp[k] = str(rdp.get(k))[:256]

    for k in ("os", "workgroup", "smb_signing_enabled", "smb_signing_required", "smbv1_detected"):
        if k in smb:
            fp[k] = smb[k]

    # Minimal AD signal from LDAP RootDSE
    if isinstance(ldap, dict):
        for k in (
            "defaultNamingContext",
            "rootDomainNamingContext",
            "dnsHostName",
            "ldapServiceName",
        ):
            if ldap.get(k):
                fp[k] = str(ldap.get(k))[:512]

    if isinstance(http, dict):
        if http.get("title"):
            fp["http_title"] = str(http.get("title"))[:256]
        if http.get("server"):
            fp["http_server"] = str(http.get("server"))[:256]
        # v3.8.8: Device fingerprinting from HTTP probe
        for k in ("device_vendor", "device_model", "device_type"):
            if http.get(k):
                fp[k] = str(http.get(k))[:64]

    if isinstance(ssh, dict):
        hostkeys = ssh.get("hostkeys")
        if isinstance(hostkeys, list) and hostkeys:
            fp["ssh_hostkeys"] = hostkeys[:5]

    return fp
