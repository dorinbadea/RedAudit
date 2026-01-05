#!/usr/bin/env python3
"""
Scanner Enrichment Logic - RedAudit
Separated from scanner.py for modularity.
"""

import re
import ipaddress
import subprocess
import html as html_module
from typing import Dict, List, Optional, Any

from redaudit.core.scanner.utils import sanitize_ip, is_ipv6
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.core.scanner.nmap import _make_runner, _is_dry_run


HTTP_IDENTITY_PORTS = (80, 443, 8080, 8443, 8000, 8888)
HTTP_IDENTITY_HTTPS_PORTS = {443, 8443, 9443, 4443}
HTTP_IDENTITY_PATHS = ("/", "/login", "/login.html", "/index.html")


def enrich_host_with_dns(host_record: Dict, extra_tools: Dict) -> None:
    """
    Enrich host record with DNS reverse lookup.
    """
    ip_str = host_record["ip"]
    host_record.setdefault("dns", {})

    if extra_tools.get("dig"):
        try:
            runner = _make_runner(timeout=5.0)
            res = runner.run(
                [extra_tools["dig"], "+short", "-x", ip_str],
                capture_output=True,
                check=False,
                text=True,
                timeout=5.0,
            )
            output = str(res.stdout or "").strip()
            if output:
                host_record["dns"]["reverse"] = output.splitlines()
        except Exception:
            pass


def enrich_host_with_whois(host_record: Dict, extra_tools: Dict) -> None:
    """
    Enrich host record with WHOIS data for public IPs.
    """
    ip_str = host_record["ip"]
    host_record.setdefault("dns", {})

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if not ip_obj.is_private and extra_tools.get("whois"):
            runner = _make_runner(timeout=15.0)
            res = runner.run(
                [extra_tools["whois"], ip_str],
                capture_output=True,
                check=False,
                text=True,
                timeout=15.0,
            )
            combined = str(res.stdout or "") or str(res.stderr or "")
            if combined:
                lines = [line for line in combined.splitlines() if line.strip()][:25]
                host_record["dns"]["whois_summary"] = "\n".join(lines)
    except Exception:
        pass


def _fetch_http_headers(
    url: str,
    extra_tools: Dict,
    *,
    dry_run: Optional[bool] = None,
    logger=None,
    proxy_manager=None,
) -> str:
    if extra_tools.get("curl"):
        args = [
            extra_tools["curl"],
            "-I",
            "-L",
            "--max-time",
            "5",
            "--connect-timeout",
            "3",
            "-sS",
        ]
        if url.startswith("https://"):
            args.append("-k")
        args.append(url)
        try:
            runner = _make_runner(
                logger=logger,
                dry_run=dry_run,
                timeout=6.0,
                command_wrapper=get_proxy_command_wrapper(proxy_manager),
            )
            res = runner.run(
                args,
                capture_output=True,
                check=False,
                text=True,
                timeout=6.0,
            )
            return str(res.stdout or "")
        except Exception:
            return ""
    if extra_tools.get("wget"):
        args = [
            extra_tools["wget"],
            "--spider",
            "-S",
            "--timeout=5",
            "--tries=1",
        ]
        if url.startswith("https://"):
            args.append("--no-check-certificate")
        args.append(url)
        try:
            runner = _make_runner(
                logger=logger,
                dry_run=dry_run,
                timeout=6.0,
                command_wrapper=get_proxy_command_wrapper(proxy_manager),
            )
            res = runner.run(
                args,
                capture_output=True,
                check=False,
                text=True,
                timeout=6.0,
            )
            return str(res.stderr or "")
        except Exception:
            return ""
    return ""


def _fetch_http_body(
    url: str,
    extra_tools: Dict,
    *,
    dry_run: Optional[bool] = None,
    logger=None,
    proxy_manager=None,
) -> str:
    if extra_tools.get("curl"):
        args = [
            extra_tools["curl"],
            "-L",
            "--max-time",
            "6",
            "--connect-timeout",
            "3",
            "-sS",
            "--range",
            "0-32767",
        ]
        if url.startswith("https://"):
            args.append("-k")
        args.append(url)
        try:
            runner = _make_runner(
                logger=logger,
                dry_run=dry_run,
                timeout=7.0,
                command_wrapper=get_proxy_command_wrapper(proxy_manager),
            )
            res = runner.run(
                args,
                capture_output=True,
                check=False,
                text=True,
                timeout=7.0,
            )
            return str(res.stdout or "")
        except Exception:
            return ""
    if extra_tools.get("wget"):
        args = [
            extra_tools["wget"],
            "-qO-",
            "--timeout=6",
            "--tries=1",
            "--max-redirect=2",
        ]
        if url.startswith("https://"):
            args.append("--no-check-certificate")
        args.append(url)
        try:
            runner = _make_runner(
                logger=logger,
                dry_run=dry_run,
                timeout=7.0,
                command_wrapper=get_proxy_command_wrapper(proxy_manager),
            )
            res = runner.run(
                args,
                capture_output=True,
                check=False,
                text=True,
                timeout=7.0,
            )
            return str(res.stdout or "")
        except Exception:
            return ""
    return ""


def http_enrichment(
    url: str,
    extra_tools: Dict,
    *,
    dry_run: Optional[bool] = None,
    logger=None,
    proxy_manager=None,
) -> Dict:
    """
    Enrich with HTTP headers using curl/wget.
    """
    data = {}

    if extra_tools.get("curl"):
        try:
            runner = _make_runner(
                logger=logger,
                dry_run=dry_run,
                timeout=15.0,
                command_wrapper=get_proxy_command_wrapper(proxy_manager),
            )
            res = runner.run(
                [extra_tools["curl"], "-I", "--max-time", "10", url],
                capture_output=True,
                check=False,
                text=True,
                timeout=15.0,
            )
            output = str(res.stdout or "").strip()
            if output:
                data["curl_headers"] = output[:2000]
        except Exception:
            pass

    if extra_tools.get("wget"):
        try:
            runner = _make_runner(
                logger=logger,
                dry_run=dry_run,
                timeout=15.0,
                command_wrapper=get_proxy_command_wrapper(proxy_manager),
            )
            res = runner.run(
                [extra_tools["wget"], "--spider", "-S", "--timeout=10", url],
                capture_output=True,
                check=False,
                text=True,
                timeout=15.0,
            )
            err = str(res.stderr or "").strip()
            if err:
                data["wget_headers"] = err[:2000]
        except Exception:
            pass

    return data


def _format_http_host(host_ip: str) -> str:
    return f"[{host_ip}]" if is_ipv6(host_ip) else host_ip


def _extract_http_server(headers: str) -> str:
    if not headers:
        return ""
    server = ""
    for line in headers.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
    return server[:200] if server else ""


def _clean_http_identity_text(text: str) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"<[^>]+>", " ", text)
    cleaned = html_module.unescape(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:200] if cleaned else ""


def _extract_http_title(html: str) -> str:
    if not html:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        title = _clean_http_identity_text(match.group(1))
        if title:
            return title
    meta_names = ("og:title", "og:site_name", "application-name", "application_name", "title")
    for name in meta_names:
        meta_match = re.search(
            rf"<meta[^>]+(?:name|property)=[\"']{re.escape(name)}[\"'][^>]*>",
            html,
            re.IGNORECASE,
        )
        if meta_match:
            content_match = re.search(
                r"content\s*=\s*[\"']([^\"']+)",
                meta_match.group(0),
                re.IGNORECASE,
            )
            if content_match:
                meta_title = _clean_http_identity_text(content_match.group(1))
                if meta_title:
                    return meta_title
    for tag in ("h1", "h2"):
        match = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", html, re.IGNORECASE | re.DOTALL)
        if match:
            heading = _clean_http_identity_text(match.group(1))
            if heading:
                return heading
    alt_match = re.search(r"<img[^>]+alt=[\"']([^\"']+)", html, re.IGNORECASE)
    if alt_match:
        alt_text = _clean_http_identity_text(alt_match.group(1))
        if alt_text and alt_text.lower() not in {"logo", "logo svg"}:
            return alt_text
    return ""


def http_identity_probe(
    host_ip: str,
    extra_tools: Dict,
    ports: Optional[List[int]] = None,
    *,
    dry_run: Optional[bool] = None,
    logger=None,
    proxy_manager=None,
) -> Dict:
    """
    Best-effort HTTP probe for hosts with no visible web ports.
    """
    safe_ip = sanitize_ip(host_ip)
    if not safe_ip or _is_dry_run(dry_run):
        return {}
    if not extra_tools.get("curl") and not extra_tools.get("wget"):
        return {}

    host = _format_http_host(safe_ip)
    ports_to_check = ports or list(HTTP_IDENTITY_PORTS)
    for port in ports_to_check:
        schemes = ("https", "http") if port in HTTP_IDENTITY_HTTPS_PORTS else ("http", "https")
        for scheme in schemes:
            server = ""
            title = ""
            for path in HTTP_IDENTITY_PATHS:
                url = f"{scheme}://{host}:{port}{path}"
                if not server:
                    headers = _fetch_http_headers(
                        url,
                        extra_tools,
                        dry_run=dry_run,
                        logger=logger,
                        proxy_manager=proxy_manager,
                    )
                    server = _extract_http_server(headers)
                if not title:
                    body = _fetch_http_body(
                        url,
                        extra_tools,
                        dry_run=dry_run,
                        logger=logger,
                        proxy_manager=proxy_manager,
                    )
                    title = _extract_http_title(body[:40000])
                if title and server:
                    break
            if title or server:
                result = {}
                if title:
                    result["http_title"] = title
                if server:
                    result["http_server"] = server
                return result

    return {}


def tls_enrichment(
    host_ip: str,
    port: int,
    extra_tools: Dict,
    *,
    dry_run: Optional[bool] = None,
    logger=None,
    proxy_manager=None,
) -> Dict:
    """
    Enrich with TLS certificate information.
    """
    data = {}

    if extra_tools.get("openssl"):
        try:
            runner = _make_runner(
                logger=logger,
                dry_run=dry_run,
                timeout=10.0,
                command_wrapper=get_proxy_command_wrapper(proxy_manager),
            )
            res = runner.run(
                [
                    extra_tools["openssl"],
                    "s_client",
                    "-connect",
                    f"{host_ip}:{port}",
                    "-servername",
                    host_ip,
                    "-brief",
                ],
                capture_output=True,
                check=False,
                text=True,
                timeout=10.0,
                input_text="",
            )
            output = str(res.stdout or "").strip()
            if output:
                data["tls_info"] = output[:2000]
        except Exception:
            pass

    return data


def exploit_lookup(service_name: str, version: str, extra_tools: Dict, logger=None) -> List[str]:
    """
    Query ExploitDB for known exploits matching service and version.
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
        runner = _make_runner(logger=logger, timeout=10.0)
        res = runner.run(
            [extra_tools["searchsploit"], "--colour", "--nmap", query],
            capture_output=True,
            check=False,
            text=True,
            timeout=10.0,
        )

        if res.returncode != 0:
            return []

        output = str(res.stdout or "")
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


def ssl_deep_analysis(
    host_ip: str,
    port: int,
    extra_tools: Dict,
    logger=None,
    timeout: int = 90,
    proxy_manager=None,
) -> Optional[Dict]:
    """
    Perform comprehensive SSL/TLS security analysis using testssl.sh.
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
            "--severity",
            "HIGH",
            f"{safe_ip}:{port}",
        ]

        runner = _make_runner(
            logger=logger,
            timeout=float(timeout),
            command_wrapper=get_proxy_command_wrapper(proxy_manager),
        )
        res = runner.run(cmd, capture_output=True, check=False, text=True, timeout=float(timeout))

        if res.timed_out:
            if logger:
                logger.warning("TestSSL timeout for %s:%d after %ds", safe_ip, port, timeout)
            return {"error": f"Analysis timeout after {timeout}s", "target": f"{safe_ip}:{port}"}

        output = str(res.stdout or "") or str(res.stderr or "")
        if not output.strip():
            return None

        # Parse output for key findings
        findings: Dict[str, Any] = {
            "target": f"{safe_ip}:{port}",
            "summary": "",
            "vulnerabilities": [],
            "weak_ciphers": [],
            "protocols": [],
        }

        lines = output.splitlines()
        for line in lines:
            line_lower = line.lower()

            # Detect vulnerabilities
            if any(
                vuln in line_lower
                for vuln in ["vulnerable", "heartbleed", "poodle", "beast", "crime", "breach"]
            ):
                if "not vulnerable" not in line_lower and "ok" not in line_lower:
                    findings["vulnerabilities"].append(line.strip()[:200])

            # Detect weak ciphers
            if "weak" in line_lower or "insecure" in line_lower:
                if "cipher" in line_lower or "encryption" in line_lower:
                    findings["weak_ciphers"].append(line.strip()[:150])

            # Detect protocols
            if any(
                proto in line_lower
                for proto in ["sslv2", "sslv3", "tls 1.0", "tls 1.1", "tls 1.2", "tls 1.3"]
            ):
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

    except Exception as exc:
        if logger:
            logger.debug("TestSSL error for %s:%d: %s", safe_ip, port, exc)
        return None


def banner_grab_fallback(
    host_ip: str,
    ports: List[int],
    extra_tools: Dict = None,
    timeout: int = 30,
    logger=None,
    proxy_manager=None,
) -> Dict[int, Dict]:
    """
    Fallback banner grabbing for unidentified services (v2.8.0).
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
        "nmap",
        "-sV",
        "--script",
        "banner,ssl-cert",
        "-p",
        port_str,
        "-Pn",
        "--host-timeout",
        "60s",
        safe_ip,
    ]

    results: Dict[int, Dict] = {}

    try:
        runner = _make_runner(
            logger=logger,
            timeout=float(timeout),
            command_wrapper=get_proxy_command_wrapper(proxy_manager),
        )
        res = runner.run(cmd, capture_output=True, check=False, text=True, timeout=float(timeout))
        if res.timed_out:
            if logger:
                logger.warning("Banner grab timeout for %s ports %s", safe_ip, port_str)
            return results
        output = str(res.stdout or "")

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

    except Exception as exc:
        if logger:
            logger.debug("Banner grab error for %s: %s", safe_ip, exc)

    return results
