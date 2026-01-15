#!/usr/bin/env python3
"""
RedAudit - NVD CVE Correlation Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.0: Query NIST NVD API 2.0 for vulnerability correlation.
Maps detected service versions to CVEs using CPE matching.
v3.0.1: Integrated with config module for API key persistence.
"""

import os
import re
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from redaudit.utils.constants import VERSION

from urllib.parse import quote as urlquote

# Import config module for API key management
try:
    from redaudit.utils.config import get_nvd_api_key as config_get_nvd_api_key

    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    config_get_nvd_api_key = None

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_TIMEOUT = 30  # seconds

# Rate limiting (without API key: 5 req/30s, with key: 50 req/30s)
NVD_RATE_LIMIT_NO_KEY = 6.0  # seconds between requests
NVD_RATE_LIMIT_WITH_KEY = 0.6  # seconds between requests

# Cache configuration
NVD_CACHE_DIR = os.path.expanduser("~/.redaudit/cache/nvd")
NVD_CACHE_TTL = 86400 * 7  # 7 days
NVD_MAX_RETRIES = 3
NVD_RETRY_BACKOFF = 2.0  # seconds


def get_api_key_from_config() -> Optional[str]:
    """
    Get NVD API key from config or environment.

    Priority:
    1. Environment variable NVD_API_KEY
    2. Config file ~/.redaudit/config.json

    Returns:
        API key string or None if not configured
    """
    if CONFIG_AVAILABLE and config_get_nvd_api_key:
        return config_get_nvd_api_key()

    # Fallback: check environment directly
    env_key = os.environ.get("NVD_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    return None


def ensure_cache_dir() -> str:
    """Create cache directory if it doesn't exist with secure permissions."""
    os.makedirs(NVD_CACHE_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(NVD_CACHE_DIR, 0o700)
    except Exception:
        # Best-effort; not fatal if we cannot chmod
        pass
    return NVD_CACHE_DIR


def get_cache_key(query: str) -> str:
    """Generate cache key from query string."""
    return hashlib.md5(query.encode()).hexdigest()


def get_cached_result(query: str) -> Optional[Dict]:
    """
    Retrieve cached NVD result if exists and not expired.

    Args:
        query: The CPE or keyword query

    Returns:
        Cached result dict or None
    """
    cache_dir = ensure_cache_dir()
    cache_file = os.path.join(cache_dir, f"{get_cache_key(query)}.json")

    if not os.path.isfile(cache_file):
        return None

    try:
        mtime = os.path.getmtime(cache_file)
        if time.time() - mtime > NVD_CACHE_TTL:
            os.remove(cache_file)
            return None

        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_to_cache(query: str, result: Dict) -> None:
    """Save NVD result to cache."""
    cache_dir = ensure_cache_dir()
    cache_file = os.path.join(cache_dir, f"{get_cache_key(query)}.json")

    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(result, f)
        try:
            os.chmod(cache_file, 0o600)
        except Exception:
            pass
    except Exception:
        pass


def build_cpe_query(product: str, version: str, vendor: str = "*") -> str:
    """
    Build CPE 2.3 string for NVD query.

    Args:
        product: Software name (e.g., "apache", "openssh")
        version: Version string (e.g., "2.4.49", "7.9")
        vendor: Vendor name (default: wildcard)

    Returns:
        CPE 2.3 formatted string
    """
    # Sanitize inputs
    product = re.sub(r"[^a-zA-Z0-9_\-.]", "", product.lower())[:50]
    version = re.sub(r"[^a-zA-Z0-9_\-.]", "", version)[:20]
    vendor = re.sub(r"[^a-zA-Z0-9_\-.]", "", vendor.lower())[:50] if vendor != "*" else "*"

    # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
    # Part 'a' = application
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def extract_product_version(service_info: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract product name and version from nmap service info.

    Args:
        service_info: Service string like "Apache httpd 2.4.49" or "OpenSSH 7.9p1"

    Returns:
        Tuple of (product, version) or (None, None)
    """
    if not service_info:
        return None, None

    # Common patterns
    patterns = [
        r"(\w+)\s+httpd?\s+(\d+\.\d+(?:\.\d+)?)",  # Apache httpd 2.4.49
        r"(\w+)\s+(\d+\.\d+(?:\.\d+)?(?:p\d+)?)",  # OpenSSH 7.9p1
        r"(\w+)/(\d+\.\d+(?:\.\d+)?)",  # nginx/1.18.0
    ]

    for pattern in patterns:
        match = re.search(pattern, service_info, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2)

    return None, None


def query_nvd(
    keyword: Optional[str] = None,
    cpe_name: Optional[str] = None,
    api_key: Optional[str] = None,
    logger=None,
) -> List[Dict]:
    """
    Query NVD API for CVEs.

    Args:
        keyword: Keyword search term
        cpe_name: CPE 2.3 string
        api_key: Optional NVD API key
        logger: Optional logger

    Returns:
        List of CVE dictionaries
    """
    if not keyword and not cpe_name:
        return []

    # Check cache first
    cache_key = keyword or cpe_name
    cached = get_cached_result(cache_key)
    if cached:
        if logger:
            logger.debug("NVD cache hit for: %s", cache_key[:50])
        return cached.get("cves", [])

    # Build query URL
    params = []
    if keyword:
        params.append(f"keywordSearch={urlquote(keyword, safe='')}")
    if cpe_name:
        params.append(f"cpeName={cpe_name}")

    url = f"{NVD_API_URL}?{'&'.join(params)}"

    req = Request(url)
    req.add_header("User-Agent", f"RedAudit/{VERSION}")

    if api_key:
        req.add_header("apiKey", api_key)

    for attempt in range(1, NVD_MAX_RETRIES + 1):
        try:
            with urlopen(req, timeout=NVD_API_TIMEOUT) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))

                    cves = []
                    for vuln in data.get("vulnerabilities", []):
                        cve_data = vuln.get("cve", {})
                        cve_id = cve_data.get("id", "")

                        # Extract CVSS score
                        cvss_score = None
                        cvss_severity = None

                        metrics = cve_data.get("metrics", {})
                        if "cvssMetricV31" in metrics:
                            cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
                            cvss_score = cvss.get("baseScore")
                            cvss_severity = cvss.get("baseSeverity")
                        elif "cvssMetricV2" in metrics:
                            cvss = metrics["cvssMetricV2"][0].get("cvssData", {})
                            cvss_score = cvss.get("baseScore")

                        # Extract description
                        descriptions = cve_data.get("descriptions", [])
                        description = ""
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")[:500]
                                break

                        cves.append(
                            {
                                "cve_id": cve_id,
                                "cvss_score": cvss_score,
                                "cvss_severity": cvss_severity,
                                "description": description,
                                "published": cve_data.get("published", ""),
                            }
                        )

                    # Cache result
                    save_to_cache(
                        cache_key, {"cves": cves, "timestamp": datetime.now().isoformat()}
                    )

                    return cves

        except HTTPError as e:
            # v4.7.2: 404 = CPE not found, don't retry (wastes time)
            if e.code == 404:
                if logger:
                    logger.debug("NVD API 404: CPE not found, skipping retries")
                break
            retryable = e.code in (429, 500, 502, 503, 504)
            if logger:
                logger.warning(
                    "NVD API error: %s (attempt %s/%s)",
                    e.code,
                    attempt,
                    NVD_MAX_RETRIES,
                )
            if not retryable or attempt == NVD_MAX_RETRIES:
                break
        except URLError as e:
            if logger:
                logger.warning(
                    "NVD network error: %s (attempt %s/%s)",
                    e.reason,
                    attempt,
                    NVD_MAX_RETRIES,
                )
            if attempt == NVD_MAX_RETRIES:
                break
        except Exception as e:
            if logger:
                logger.debug("NVD query failed: %s (attempt %s/%s)", e, attempt, NVD_MAX_RETRIES)
            if attempt == NVD_MAX_RETRIES:
                break

        time.sleep(NVD_RETRY_BACKOFF * attempt)

    return []


def enrich_port_with_cves(port_info: Dict, api_key: Optional[str] = None, logger=None) -> Dict:
    """
    Enrich a port record with CVE information.

    Args:
        port_info: Port dictionary with 'service', 'version' etc.
        api_key: Optional NVD API key
        logger: Optional logger

    Returns:
        Port info dict with added 'cves' list
    """
    service = port_info.get("service", "")
    version = port_info.get("version", "")
    product = port_info.get("product", "")

    def cpe_to_23(cpe: str) -> Optional[str]:
        s = (cpe or "").strip()
        if not s:
            return None
        if s.startswith("cpe:2.3:"):
            return s
        # Nmap often returns legacy CPE 2.2 URIs like: cpe:/a:vendor:product:version
        if s.startswith("cpe:/"):
            rest = s[len("cpe:/") :]
            parts = rest.split(":")
            if len(parts) < 3:
                return None
            part = (parts[0] or "*").strip()  # a|o|h
            vendor = (parts[1] or "*").strip()
            prod = (parts[2] or "*").strip()
            ver = (parts[3] if len(parts) > 3 and parts[3] else "*").strip()
            fields = [part, vendor, prod, ver] + ["*"] * 7
            return "cpe:2.3:" + ":".join(fields)
        return None

    # Prefer Nmap-reported CPE when present (works even if version string is missing).
    cpe_value = port_info.get("cpe")
    cpe_candidates: List[str] = []
    if isinstance(cpe_value, str):
        cpe_candidates = [cpe_value]
    elif isinstance(cpe_value, list):
        cpe_candidates = [c for c in cpe_value if isinstance(c, str)]

    cpe_23 = None
    for c in cpe_candidates:
        cpe_23 = cpe_to_23(c)
        if cpe_23:
            break

    # Try to extract product/version when one of them is missing.
    service_info = " ".join(
        str(x)
        for x in (
            product,
            version,
            port_info.get("extrainfo", ""),
            service,
        )
        if x
    )
    if service_info and (not product or not version):
        extracted_product, extracted_version = extract_product_version(service_info)
        if not product and extracted_product:
            product = extracted_product
        if not version and extracted_version:
            version = extracted_version

    if not product:
        product = service.split()[0] if service else ""

    if not cpe_23 and (not product or not version):
        return port_info

    # Rate limiting
    rate_limit = NVD_RATE_LIMIT_WITH_KEY if api_key else NVD_RATE_LIMIT_NO_KEY

    # Query NVD (avoid querying wildcard-version CPEs when we don't know the version).
    cves = []
    if cpe_23:
        parts = cpe_23.split(":")
        cpe_version = parts[5] if len(parts) > 5 else ""
        if cpe_version in ("*", "-", ""):
            if not version:
                return port_info
            sanitized_version = re.sub(r"[^a-zA-Z0-9_\-.]", "", str(version))[:20]
            if not sanitized_version:
                return port_info
            if len(parts) > 5:
                parts[5] = sanitized_version
                cpe_23 = ":".join(parts)
        cves = query_nvd(cpe_name=cpe_23, api_key=api_key, logger=logger)
    else:
        cpe = build_cpe_query(product, version)
        cves = query_nvd(cpe_name=cpe, api_key=api_key, logger=logger)

    # If CPE query failed, try keyword search
    if not cves and not cpe_23:
        keyword = f"{product} {version}"
        cves = query_nvd(keyword=keyword, api_key=api_key, logger=logger)
        time.sleep(rate_limit)
    else:
        time.sleep(rate_limit)

    if cves:
        port_info["cves"] = cves[:10]  # Limit to top 10
        port_info["cve_count"] = len(cves)

        # Calculate max severity
        max_score = max((c.get("cvss_score") or 0 for c in cves), default=0)
        if max_score >= 9.0:
            port_info["cve_max_severity"] = "CRITICAL"
        elif max_score >= 7.0:
            port_info["cve_max_severity"] = "HIGH"
        elif max_score >= 4.0:
            port_info["cve_max_severity"] = "MEDIUM"
        elif max_score > 0:
            port_info["cve_max_severity"] = "LOW"

    return port_info


def enrich_host_with_cves(host_record: Dict, api_key: Optional[str] = None, logger=None) -> Dict:
    """
    Enrich a host record with CVE information for all services.

    Args:
        host_record: Host dictionary with 'ports' list
        api_key: Optional NVD API key
        logger: Optional logger

    Returns:
        Host record with CVE-enriched ports
    """
    from redaudit.core.models import Host

    host_obj = host_record if isinstance(host_record, Host) else None
    ports = host_obj.ports if host_obj is not None else host_record.get("ports", [])

    for i, port_info in enumerate(ports):
        # Check services with version info OR reported CPE (Nmap may provide CPE without a version string).
        cpe_value = port_info.get("cpe")
        has_cpe = False
        if isinstance(cpe_value, str):
            has_cpe = bool(cpe_value.strip())
        elif isinstance(cpe_value, list):
            has_cpe = any(isinstance(c, str) and c.strip() for c in cpe_value)
        if port_info.get("version") or has_cpe:
            ports[i] = enrich_port_with_cves(port_info, api_key, logger)

    # Calculate host-level CVE summary
    total_cves = sum(p.get("cve_count", 0) for p in ports)
    critical_count = sum(1 for p in ports if p.get("cve_max_severity") == "CRITICAL")
    high_count = sum(1 for p in ports if p.get("cve_max_severity") == "HIGH")

    if total_cves > 0:
        summary = {
            "total": total_cves,
            "critical": critical_count,
            "high": high_count,
        }
        if host_obj is not None:
            host_obj.cve_summary = summary
        else:
            host_record["cve_summary"] = summary

    if host_obj is not None:
        host_obj.ports = ports
        return host_obj
    return host_record


def clear_cache() -> int:
    """
    Clear the NVD cache directory.

    Returns:
        Number of files removed
    """
    count = 0
    try:
        for f in os.listdir(NVD_CACHE_DIR):
            filepath = os.path.join(NVD_CACHE_DIR, f)
            if os.path.isfile(filepath):
                os.remove(filepath)
                count += 1
    except Exception:
        pass
    return count
