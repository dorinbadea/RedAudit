#!/usr/bin/env python3
"""
RedAudit - Webhook Alerting Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.3: Send real-time alerts to external services (Slack, Teams, PagerDuty, etc.)
"""

import json
import logging
from datetime import datetime
from typing import Dict, Optional, Any

import requests

from redaudit.utils.constants import VERSION

logger = logging.getLogger(__name__)

# Severity thresholds for alerting
ALERT_SEVERITIES = {"critical", "high"}


def build_alert_payload(
    finding: Dict,
    host: str,
    scan_target: str = "",
    scan_mode: str = "",
) -> Dict[str, Any]:
    """
    Build a standardized alert payload for webhook delivery.
    
    Args:
        finding: Vulnerability finding dictionary
        host: Host IP where finding was detected
        scan_target: Original scan target (CIDR)
        scan_mode: Scan mode used
        
    Returns:
        Webhook payload dictionary
    """
    severity = finding.get("severity", "info").lower()
    
    # Extract meaningful title
    title = finding.get("descriptive_title") or finding.get("url") or "Security Finding"
    
    # Build payload compatible with common webhook formats
    payload = {
        "source": "RedAudit",
        "version": VERSION,
        "timestamp": datetime.now().isoformat(),
        "event_type": "security.finding",
        "alert": {
            "severity": severity.upper(),
            "host": host,
            "title": title[:200],
            "category": finding.get("category", "unknown"),
            "url": finding.get("url", ""),
            "port": finding.get("port", ""),
        },
        "context": {
            "scan_target": scan_target,
            "scan_mode": scan_mode,
        },
        "details": {},
    }
    
    # Add tool-specific details if available
    if finding.get("nikto_findings"):
        payload["details"]["nikto_count"] = len(finding["nikto_findings"])
        payload["details"]["nikto_sample"] = finding["nikto_findings"][:3]
    
    if finding.get("testssl_analysis"):
        payload["details"]["testssl"] = finding["testssl_analysis"].get("summary", "")
    
    if finding.get("cve_ids"):
        payload["details"]["cves"] = finding["cve_ids"][:5]
    
    return payload


def send_webhook(
    url: str,
    payload: Dict[str, Any],
    timeout: int = 10,
    headers: Optional[Dict[str, str]] = None,
) -> bool:
    """
    Send a webhook POST request with JSON payload.
    
    Args:
        url: Webhook endpoint URL
        payload: JSON-serializable payload
        timeout: Request timeout in seconds
        headers: Optional additional headers
        
    Returns:
        True if request succeeded (2xx response), False otherwise
    """
    if not url:
        return False
    
    request_headers = {
        "Content-Type": "application/json",
        "User-Agent": f"RedAudit/{VERSION}",
    }
    if headers:
        request_headers.update(headers)
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers=request_headers,
            timeout=timeout,
        )
        
        if response.ok:
            logger.debug("Webhook sent successfully to %s", url)
            return True
        else:
            logger.warning(
                "Webhook failed: %s %s - %s",
                response.status_code,
                response.reason,
                response.text[:100],
            )
            return False
            
    except requests.exceptions.Timeout:
        logger.warning("Webhook timeout after %ds: %s", timeout, url)
        return False
    except requests.exceptions.RequestException as e:
        logger.warning("Webhook error: %s", e)
        return False


def should_alert(finding: Dict) -> bool:
    """
    Determine if a finding should trigger a webhook alert.
    
    Args:
        finding: Vulnerability finding dictionary
        
    Returns:
        True if finding severity meets threshold
    """
    severity = finding.get("severity", "info").lower()
    return severity in ALERT_SEVERITIES


def process_findings_for_alerts(
    results: Dict,
    webhook_url: str,
    config: Dict,
) -> int:
    """
    Process scan results and send alerts for high-severity findings.
    
    Args:
        results: Complete scan results dictionary
        webhook_url: Webhook endpoint URL
        config: Scan configuration dictionary
        
    Returns:
        Number of alerts sent
    """
    if not webhook_url:
        return 0
    
    alerts_sent = 0
    scan_target = ",".join(config.get("target_networks", []))
    scan_mode = config.get("scan_mode", "")
    
    for vuln_entry in results.get("vulnerabilities", []):
        host = vuln_entry.get("host", "")
        
        for finding in vuln_entry.get("vulnerabilities", []):
            if should_alert(finding):
                payload = build_alert_payload(
                    finding=finding,
                    host=host,
                    scan_target=scan_target,
                    scan_mode=scan_mode,
                )
                
                if send_webhook(webhook_url, payload):
                    alerts_sent += 1
    
    if alerts_sent > 0:
        logger.info("Sent %d webhook alerts to %s", alerts_sent, webhook_url)
    
    return alerts_sent
