"""
RedAudit - Auditor vulnerability component.
"""

from __future__ import annotations

import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from typing import Any, Dict, List, Tuple

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.core.scanner import http_enrichment, ssl_deep_analysis, tls_enrichment


class AuditorVuln:
    """Vulnerability scanning mixin for Auditor class.

    Attributes defined here are provided by the composed Auditor class at runtime.
    """

    results: Dict[str, Any]
    extra_tools: Dict[str, Any]
    config: Dict[str, Any]
    logger: Any
    current_phase: str
    ui: Any  # UIManager, provided by Auditor composition
    proxy_manager: Any  # ProxyManager, provided by Auditor composition

    def _set_ui_detail(self, detail: str) -> None:
        """Set UI detail - provided by Auditor composition."""
        ...

    @staticmethod
    def _parse_url_target(value: object) -> Tuple[str, int, str]:
        if not isinstance(value, str):
            return "", 0, ""
        raw = value.strip()
        if not raw:
            return "", 0, ""
        if "://" not in raw:
            host = raw
            port = 0
            scheme = ""
            if raw.count(":") == 1:
                host_part, port_part = raw.split(":", 1)
                host = host_part.strip()
                try:
                    port = int(port_part)
                except Exception:
                    port = 0
            return host, port, scheme
        try:
            from urllib.parse import urlparse

            parsed = urlparse(raw)
            host = parsed.hostname or ""
            port = parsed.port or 0
            scheme = parsed.scheme or ""
            if not port:
                if scheme == "https":
                    port = 443
                elif scheme == "http":
                    port = 80
            return host, port, scheme
        except Exception:
            return "", 0, ""

    @staticmethod
    def _normalize_host_info(host_info: Any) -> Dict[str, Any]:
        from redaudit.core.models import Host

        if isinstance(host_info, Host):
            return host_info.to_dict()
        return host_info

    def _merge_nuclei_findings(self, findings: List[Dict[str, Any]]) -> int:
        if not findings:
            return 0
        host_map: Dict[str, Dict[str, Any]] = {}
        for entry in self.results.get("vulnerabilities", []):
            if not isinstance(entry, dict):
                continue
            host = entry.get("host")
            if host and isinstance(entry.get("vulnerabilities"), list):
                host_map[str(host)] = entry

        merged = 0
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            matched_at = finding.get("matched_at") or finding.get("host") or ""
            host, port, scheme = self._parse_url_target(str(matched_at))
            if not host:
                host, port, scheme = self._parse_url_target(str(finding.get("host") or ""))
            if not host:
                continue

            name = finding.get("name") or finding.get("template_id") or "nuclei"
            vuln = {
                "url": matched_at or "",
                "port": port or 0,
                "severity": finding.get("severity", "info"),
                "category": "vuln",
                "source": "nuclei",
                "template_id": finding.get("template_id"),
                "name": name,
                "description": finding.get("description", ""),
                "matched_at": matched_at or "",
                "matcher_name": finding.get("matcher_name", ""),
                "reference": finding.get("reference", []),
                "tags": finding.get("tags", []),
                "cve_ids": finding.get("cve_ids", []),
                "descriptive_title": f"Nuclei: {name}",
            }
            if scheme:
                vuln["scheme"] = scheme

            entry = host_map.get(host)
            if not entry:
                entry = {"host": host, "vulnerabilities": []}
                self.results.setdefault("vulnerabilities", []).append(entry)
                host_map[host] = entry
            entry["vulnerabilities"].append(vuln)
            merged += 1
        return merged

    def _estimate_vuln_budget_s(self, host_info: Dict[str, Any]) -> float:
        """
        Timeout-aware upper bound for vulnerability scanning on a host.

        Built from per-tool defaults and scaled by scan mode.
        """
        ports = host_info.get("ports", []) if isinstance(host_info, dict) else []
        if not ports:
            return 0.0
        has_http = any("http" in str(p.get("service", "")).lower() for p in ports)
        has_tls = any("ssl" in str(p.get("service", "")).lower() for p in ports)
        has_whatweb = bool(self.extra_tools.get("whatweb"))
        has_nikto = bool(self.extra_tools.get("nikto"))
        has_testssl = bool(self.extra_tools.get("testssl.sh"))
        is_full = self.config.get("scan_mode") == "completo"

        budget = 0.0
        for p in ports:
            try:
                port = int(p.get("port", 0) or 0)
            except Exception:
                port = 0
            service = str(p.get("service", "") or "")
            service_l = service.lower()
            is_https = ("https" in service_l) or ("ssl" in service_l) or port == 443

            if has_http:
                budget += 15.0
            if has_tls and is_https:
                budget += 10.0
            if has_whatweb:
                budget += 30.0
            if is_full and has_nikto:
                budget += 150.0
            if is_full and has_testssl and is_https:
                budget += 90.0

        return max(5.0, budget)

    def scan_vulnerabilities_web(self, host_info, status_callback=None):
        """Scan web vulnerabilities on a host.

        v4.1: Parallelizes testssl, whatweb, and nikto execution per port
        for 2-3x faster vulnerability detection.
        """
        host_info = self._normalize_host_info(host_info)
        web_ports = [p for p in host_info.get("ports", []) if p.get("is_web_service")]
        if not web_ports:
            return None

        ip = host_info["ip"]
        vulns = []

        def _update_status(msg):
            if status_callback:
                status_callback(msg)
            else:
                self._set_ui_detail(msg)

        for p in web_ports:
            port = p["port"]
            service = p["service"].lower()
            # v3.6.1: Expanded HTTPS detection for non-standard ports
            HTTPS_PORTS = {443, 8443, 4443, 9443, 49443}
            scheme = "https" if port in HTTPS_PORTS or "ssl" in service else "http"
            url = f"{scheme}://{ip}:{port}/"
            finding = {"url": url, "port": port}

            # HTTP enrichment (always sequential - quick)
            _update_status(f"[http] {ip}:{port}")
            http_data = http_enrichment(
                url,
                self.extra_tools,
                dry_run=bool(self.config.get("dry_run", False)),
                logger=self.logger,
                proxy_manager=getattr(self, "proxy_manager", None),
            )
            finding.update(http_data)

            # TLS enrichment (always sequential - quick)
            if scheme == "https":
                _update_status(f"[tls] {ip}:{port}")
                tls_data = tls_enrichment(
                    ip,
                    port,
                    self.extra_tools,
                    dry_run=bool(self.config.get("dry_run", False)),
                    logger=self.logger,
                    proxy_manager=getattr(self, "proxy_manager", None),
                )
                finding.update(tls_data)

            # v4.1: Parallel execution of slow tools (testssl, whatweb, nikto)
            is_full_mode = self.config["scan_mode"] == "completo"
            parallel_vuln_enabled = not self.config.get("no_parallel_vuln", False)

            if parallel_vuln_enabled and is_full_mode:
                # Run testssl, whatweb, nikto concurrently
                parallel_results = self._run_vuln_tools_parallel(
                    ip, port, url, scheme, finding, status_callback=_update_status
                )
                finding.update(parallel_results)
            else:
                # Sequential fallback (legacy behavior)
                self._run_vuln_tools_sequential(
                    ip, port, url, scheme, finding, status_callback=_update_status
                )

            if len(finding) > 2:
                vulns.append(finding)

        return {"host": ip, "vulnerabilities": vulns} if vulns else None

    def _run_vuln_tools_parallel(
        self,
        ip: str,
        port: int,
        url: str,
        scheme: str,
        finding: Dict[str, Any],
        status_callback=None,
    ) -> Dict[str, Any]:
        """v4.1: Run testssl, whatweb, nikto in parallel for faster scanning."""
        results: Dict[str, Any] = {}

        def _update(tool_name):
            if status_callback:
                status_callback(f"[{tool_name}] {ip}:{port}")
            else:
                self._set_ui_detail(f"[{tool_name}] {ip}:{port}")

        def run_testssl():
            if scheme != "https" or not self.extra_tools.get("testssl.sh"):
                return {}
            _update("testssl")
            ssl_analysis = ssl_deep_analysis(
                ip,
                port,
                self.extra_tools,
                self.logger,
                proxy_manager=getattr(self, "proxy_manager", None),
            )
            if ssl_analysis:
                return {"testssl_analysis": ssl_analysis}
            return {}

        def run_whatweb():
            if not self.extra_tools.get("whatweb"):
                return {}
            try:
                _update("whatweb")
                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=bool(self.config.get("dry_run", False)),
                    default_timeout=30.0,
                    default_retries=0,
                    backoff_base_s=0.0,
                    redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                    command_wrapper=get_proxy_command_wrapper(getattr(self, "proxy_manager", None)),
                )
                res = runner.run(
                    [self.extra_tools["whatweb"], "-q", "-a", "3", url],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=30.0,
                )
                if not res.timed_out:
                    output = str(res.stdout or "").strip()
                    if output:
                        return {"whatweb": output[:2000]}
            except Exception:
                if self.logger:
                    self.logger.debug("WhatWeb scan failed for %s", url, exc_info=True)
            return {}

        def run_nikto():
            if not self.extra_tools.get("nikto"):
                return {}

            # v4.1: Pre-filter CDN/proxy hosts to reduce false positives
            CDN_PROXY_INDICATORS = {
                "cloudflare",
                "akamai",
                "cloudfront",
                "fastly",
                "varnish",
                "nginx",  # Only when combined with CDN headers
                "imperva",
                "incapsula",
                "sucuri",
                "aws",
            }

            server_header = str(finding.get("server", "")).lower()
            headers_raw = str(finding.get("headers", "")).lower()

            is_cdn_proxy = any(cdn in server_header for cdn in CDN_PROXY_INDICATORS)
            if not is_cdn_proxy:
                cdn_headers = ["cf-ray", "x-amz-cf-id", "x-akamai", "x-varnish", "x-sucuri"]
                is_cdn_proxy = any(h in headers_raw for h in cdn_headers)

            if is_cdn_proxy:
                if self.logger:
                    self.logger.info(
                        "Skipping Nikto for %s:%d - CDN/proxy detected (%s)",
                        ip,
                        port,
                        server_header[:50] if server_header else "cdn-headers",
                    )
                return {"nikto_skipped": "cdn_proxy_detected", "nikto_server": server_header[:100]}

            try:
                _update("nikto")
                from redaudit.core.verify_vuln import filter_nikto_false_positives

                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=bool(self.config.get("dry_run", False)),
                    default_timeout=150.0,
                    default_retries=0,
                    backoff_base_s=0.0,
                    redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                    command_wrapper=get_proxy_command_wrapper(getattr(self, "proxy_manager", None)),
                )
                res = runner.run(
                    [self.extra_tools["nikto"], "-h", url, "-maxtime", "300s"],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=330.0,
                )
                if not res.timed_out:
                    output = str(res.stdout or "") or str(res.stderr or "")
                    if output:
                        findings_list = [line for line in output.splitlines() if "+ " in line][:20]
                        if findings_list:
                            original_count = len(findings_list)
                            verified = filter_nikto_false_positives(
                                findings_list,
                                url,
                                self.extra_tools,
                                self.logger,
                                proxy_manager=getattr(self, "proxy_manager", None),
                            )
                            if verified:
                                result = {"nikto_findings": verified}
                                filtered = original_count - len(verified)
                                if filtered > 0:
                                    result["nikto_filtered_count"] = filtered
                                return result
            except Exception:
                if self.logger:
                    self.logger.debug("Nikto scan failed for %s", url, exc_info=True)
            return {}

        def run_sqlmap():
            import shutil

            sqlmap_path = self.extra_tools.get("sqlmap") or shutil.which("sqlmap")
            if not sqlmap_path:
                return {}

            try:
                _update("sqlmap")
                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=bool(self.config.get("dry_run", False)),
                    default_timeout=120.0,
                    default_retries=0,
                    backoff_base_s=0.0,
                    redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                )
                res = runner.run(
                    [
                        sqlmap_path,
                        "-u",
                        url,
                        "--batch",
                        "--crawl=1",
                        "--forms",
                        "--smart",
                        f"--risk={self.config.sqlmap_risk}",
                        f"--level={self.config.sqlmap_level}",
                        "--timeout=10",
                        "--retries=1",
                        "--random-agent",
                        "--output-dir=/tmp/sqlmap_output",
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=120.0,
                )
                if not res.timed_out:
                    output = str(res.stdout or "")
                    sqli_indicators = [
                        "is vulnerable",
                        "injectable",
                        "Parameter:",
                        "Type: ",
                        "sql injection",
                    ]
                    findings = []
                    for line in output.splitlines():
                        line_lower = line.lower()
                        if any(ind.lower() in line_lower for ind in sqli_indicators):
                            findings.append(line.strip()[:200])

                    if findings:
                        return {"sqlmap_findings": findings[:10]}
            except Exception:
                if self.logger:
                    self.logger.debug("Sqlmap scan failed for %s", url, exc_info=True)
            return {}

        def run_zap():
            import shutil
            import os

            if not self.config.get("zap_enabled"):
                return {}

            zap_path = self.extra_tools.get("zap.sh") or shutil.which("zap.sh")
            if not zap_path:
                return {}

            try:
                _update("zap")
                safe_url = url.replace("://", "_").replace(":", "_").replace("/", "_")
                report_path = f"/tmp/zap_report_{safe_url}.html"

                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=bool(self.config.get("dry_run", False)),
                    default_timeout=300.0,
                    default_retries=0,
                    backoff_base_s=0.0,
                )

                res = runner.run(
                    [
                        zap_path,
                        "-cmd",
                        "-quickurl",
                        url,
                        "-quickout",
                        report_path,
                        "-quickprogress",
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=300.0,
                )

                if not res.timed_out:
                    if os.path.exists(report_path):
                        return {"zap_report": report_path}
            except Exception:
                if self.logger:
                    self.logger.debug("ZAP scan failed for %s", url, exc_info=True)
            return {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(run_testssl),
                executor.submit(run_whatweb),
                executor.submit(run_nikto),
                executor.submit(run_sqlmap),
                executor.submit(run_zap),
            ]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.update(result)
                except Exception as e:
                    if self.logger:
                        self.logger.debug("Parallel vuln tool error: %s", e, exc_info=True)

        return results

    def _run_vuln_tools_sequential(
        self,
        ip: str,
        port: int,
        url: str,
        scheme: str,
        finding: Dict[str, Any],
        status_callback=None,
    ) -> None:
        """Legacy sequential execution of vuln tools (fallback)."""

        def _update(tool_name):
            if status_callback:
                status_callback(f"[{tool_name}] {ip}:{port}")
            else:
                self._set_ui_detail(f"[{tool_name}] {ip}:{port}")

        # TestSSL deep analysis (only in completo mode)
        if self.config["scan_mode"] == "completo" and self.extra_tools.get("testssl.sh"):
            if scheme == "https":
                self.current_phase = f"vulns:testssl:{ip}:{port}"
                _update("testssl")
                self.ui.print_status(
                    f"[testssl] {ip}:{port} → {self.ui.t('testssl_analysis', ip, port)}", "INFO"
                )
                ssl_analysis = ssl_deep_analysis(
                    ip,
                    port,
                    self.extra_tools,
                    self.logger,
                    proxy_manager=getattr(self, "proxy_manager", None),
                )
                if ssl_analysis:
                    finding["testssl_analysis"] = ssl_analysis
                    if ssl_analysis.get("vulnerabilities"):
                        self.ui.print_status(
                            f"⚠️  SSL/TLS vulnerabilities detected on {ip}:{port}", "WARNING"
                        )

        # WhatWeb
        if self.extra_tools.get("whatweb"):
            try:
                self.current_phase = f"vulns:whatweb:{ip}:{port}"
                _update("whatweb")
                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=bool(self.config.get("dry_run", False)),
                    default_timeout=30.0,
                    default_retries=0,
                    backoff_base_s=0.0,
                    redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                    command_wrapper=get_proxy_command_wrapper(getattr(self, "proxy_manager", None)),
                )
                res = runner.run(
                    [self.extra_tools["whatweb"], "-q", "-a", "3", url],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=30.0,
                )
                if not res.timed_out:
                    output = str(res.stdout or "").strip()
                    if output:
                        finding["whatweb"] = output[:2000]
            except Exception:
                if self.logger:
                    self.logger.debug("WhatWeb scan failed for %s", url, exc_info=True)

        # Nikto (only in full mode)
        if self.config["scan_mode"] == "completo" and self.extra_tools.get("nikto"):
            try:
                self.current_phase = f"vulns:nikto:{ip}:{port}"
                _update("nikto")
                from redaudit.core.verify_vuln import filter_nikto_false_positives

                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=bool(self.config.get("dry_run", False)),
                    default_timeout=150.0,
                    default_retries=0,
                    backoff_base_s=0.0,
                    redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                    command_wrapper=get_proxy_command_wrapper(getattr(self, "proxy_manager", None)),
                )
                res = runner.run(
                    [self.extra_tools["nikto"], "-h", url, "-maxtime", "300s"],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=330.0,
                )
                if not res.timed_out:
                    output = str(res.stdout or "") or str(res.stderr or "")
                    if output:
                        findings_list = [line for line in output.splitlines() if "+ " in line][:20]
                        if findings_list:
                            original_count = len(findings_list)
                            verified = filter_nikto_false_positives(
                                findings_list,
                                url,
                                self.extra_tools,
                                self.logger,
                                proxy_manager=getattr(self, "proxy_manager", None),
                            )
                            if verified:
                                finding["nikto_findings"] = verified
                                filtered = original_count - len(verified)
                                if filtered > 0:
                                    finding["nikto_filtered_count"] = filtered
                                    self.ui.print_status(
                                        f"[nikto] {ip}:{port} → Filtered {filtered}/{original_count} false positives",
                                        "INFO",
                                    )
            except Exception:
                if self.logger:
                    self.logger.debug("Nikto scan failed for %s", url, exc_info=True)

    def scan_vulnerabilities_concurrent(self, host_results):
        """Scan vulnerabilities on multiple hosts concurrently with progress bar."""
        normalized_hosts = [self._normalize_host_info(h) for h in (host_results or [])]
        # v4.0.4: Include hosts with HTTP fingerprint even if web_ports_count == 0
        web_hosts = [
            h
            for h in normalized_hosts
            if h.get("web_ports_count", 0) > 0
            or (h.get("agentless_fingerprint") or {}).get("http_title")
            or (h.get("agentless_fingerprint") or {}).get("http_server")
        ]
        if not web_hosts:
            return

        budgets = {h["ip"]: self._estimate_vuln_budget_s(h) for h in web_hosts if h.get("ip")}

        self.current_phase = "vulns"
        self._set_ui_detail("web vuln scan")
        self.ui.print_status(self.ui.t("vuln_analysis", len(web_hosts)), "HEADER")
        workers = min(3, self.config["threads"])
        workers = max(1, int(workers))

        # Check for rich capability
        use_rich = self.ui.get_progress_console() is not None

        # Status tracking for granular detail
        host_status_map = {}

        def _runner(h):
            def _cb(msg):
                host_status_map[h["ip"]] = msg

            return self.scan_vulnerabilities_web(h, status_callback=_cb)

        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {}
                for h in web_hosts:
                    ip = h["ip"]
                    futures[executor.submit(_runner, h)] = ip
                    host_status_map[ip] = "Starting..."

                total = len(futures)
                done = 0

                if use_rich and total > 0:
                    # v4.3.0: Detailed progress - one bar per host
                    progress = self.ui.get_standard_progress(transient=False)
                    if progress:
                        with progress:
                            host_tasks = {}
                            # Create a task for each host
                            for ip in host_status_map:
                                task_id = progress.add_task(
                                    f"[cyan]  {ip}",
                                    total=100,
                                    start=True,
                                    detail="Starting...",
                                )
                                host_tasks[ip] = (task_id, time.time())

                            pending = set(futures)
                            while pending:
                                if self.interrupted:
                                    for pending_fut in pending:
                                        pending_fut.cancel()
                                    break

                                completed, pending = wait(
                                    pending, timeout=0.25, return_when=FIRST_COMPLETED
                                )

                                # Update progress details from host_status_map
                                now = time.time()
                                for ip, status in host_status_map.items():
                                    task_id, start_time = host_tasks[ip]
                                    budget = budgets.get(ip, 300.0)
                                    elapsed = now - start_time
                                    # Estimate percentage based on budget (cap 95%)
                                    pct = min(95, int((elapsed / max(1, budget)) * 100))
                                    # Update bar: If done, it will be handled in completed loop
                                    if ip not in [futures[f] for f in completed]:
                                        progress.update(
                                            task_id,
                                            completed=pct,
                                            detail=f"[yellow]{status}[/]",
                                        )

                                for fut in completed:
                                    host_ip = futures[fut]
                                    task_id, _ = host_tasks[host_ip]
                                    try:
                                        res = fut.result()
                                        if res:
                                            self.results["vulnerabilities"].append(res)
                                            vuln_count = len(res.get("vulnerabilities", []))
                                            count_str = (
                                                f"({vuln_count} vulns)" if vuln_count else "✓"
                                            )
                                            # Final green update
                                            progress.update(
                                                task_id,
                                                completed=100,
                                                description=f"[green]✅ {host_ip} {count_str}",
                                                detail="",
                                            )
                                        else:
                                            progress.update(
                                                task_id,
                                                completed=100,
                                                description=f"[green]✅ {host_ip} (Clean)",
                                                detail="",
                                            )
                                    except Exception as exc:
                                        self.logger.error(
                                            "Vuln worker error for %s: %s", host_ip, exc
                                        )
                                        progress.update(
                                            task_id,
                                            completed=100,
                                            description=f"[red]❌ {host_ip}",
                                            detail=str(exc),
                                        )
                                    done += 1
                else:
                    # Fallback without rich
                    for fut in as_completed(futures):
                        host_ip = futures[fut]
                        try:
                            res = fut.result()
                            if res:
                                self.results["vulnerabilities"].append(res)
                        except Exception as exc:
                            if self.logger:
                                self.logger.error("Vuln error %s: %s", host_ip, exc)
