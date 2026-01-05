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
    results: Dict[str, Any]
    extra_tools: Dict[str, Any]
    config: Dict[str, Any]
    logger: Any

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

    def scan_vulnerabilities_web(self, host_info):
        """Scan web vulnerabilities on a host."""
        host_info = self._normalize_host_info(host_info)
        web_ports = [p for p in host_info.get("ports", []) if p.get("is_web_service")]
        if not web_ports:
            return None

        ip = host_info["ip"]
        vulns = []

        for p in web_ports:
            port = p["port"]
            service = p["service"].lower()
            # v3.6.1: Expanded HTTPS detection for non-standard ports
            HTTPS_PORTS = {443, 8443, 4443, 9443, 49443}
            scheme = "https" if port in HTTPS_PORTS or "ssl" in service else "http"
            url = f"{scheme}://{ip}:{port}/"
            finding = {"url": url, "port": port}

            # HTTP enrichment
            http_data = http_enrichment(
                url,
                self.extra_tools,
                dry_run=bool(self.config.get("dry_run", False)),
                logger=self.logger,
                proxy_manager=getattr(self, "proxy_manager", None),
            )
            finding.update(http_data)

            # TLS enrichment
            if scheme == "https":
                tls_data = tls_enrichment(
                    ip,
                    port,
                    self.extra_tools,
                    dry_run=bool(self.config.get("dry_run", False)),
                    logger=self.logger,
                    proxy_manager=getattr(self, "proxy_manager", None),
                )
                finding.update(tls_data)

                # TestSSL deep analysis (only in completo mode)
                if self.config["scan_mode"] == "completo" and self.extra_tools.get("testssl.sh"):
                    self.current_phase = f"vulns:testssl:{ip}:{port}"
                    self._set_ui_detail(f"[testssl] {ip}:{port}")
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
                        # Alert if vulnerabilities found
                        if ssl_analysis.get("vulnerabilities"):
                            self.ui.print_status(
                                f"⚠️  SSL/TLS vulnerabilities detected on {ip}:{port}", "WARNING"
                            )

            # WhatWeb
            if self.extra_tools.get("whatweb"):
                try:
                    self.current_phase = f"vulns:whatweb:{ip}:{port}"
                    self._set_ui_detail(f"[whatweb] {ip}:{port}")
                    runner = CommandRunner(
                        logger=self.logger,
                        dry_run=bool(self.config.get("dry_run", False)),
                        default_timeout=30.0,
                        default_retries=0,
                        backoff_base_s=0.0,
                        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                        command_wrapper=get_proxy_command_wrapper(
                            getattr(self, "proxy_manager", None)
                        ),
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
            # v2.9: Smart-Check integration for false positive filtering
            if self.config["scan_mode"] == "completo" and self.extra_tools.get("nikto"):
                try:
                    self.current_phase = f"vulns:nikto:{ip}:{port}"
                    self._set_ui_detail(f"[nikto] {ip}:{port}")
                    from redaudit.core.verify_vuln import filter_nikto_false_positives

                    runner = CommandRunner(
                        logger=self.logger,
                        dry_run=bool(self.config.get("dry_run", False)),
                        default_timeout=150.0,
                        default_retries=0,
                        backoff_base_s=0.0,
                        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                        command_wrapper=get_proxy_command_wrapper(
                            getattr(self, "proxy_manager", None)
                        ),
                    )
                    res = runner.run(
                        [self.extra_tools["nikto"], "-h", url, "-maxtime", "120s", "-Tuning", "x"],
                        capture_output=True,
                        check=False,
                        text=True,
                        timeout=150.0,
                    )
                    if not res.timed_out:
                        output = str(res.stdout or "") or str(res.stderr or "")
                        if output:
                            findings_list = [line for line in output.splitlines() if "+ " in line][
                                :20
                            ]
                            if findings_list:
                                # v2.9: Filter false positives using Smart-Check
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
                                    # Track how many were filtered
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

            if len(finding) > 2:
                vulns.append(finding)

        return {"host": ip, "vulnerabilities": vulns} if vulns else None

    def scan_vulnerabilities_concurrent(self, host_results):
        """Scan vulnerabilities on multiple hosts concurrently with progress bar."""
        normalized_hosts = [self._normalize_host_info(h) for h in (host_results or [])]
        # v4.0.4: Include hosts with HTTP fingerprint even if web_ports_count == 0
        # This fixes detection gap for hosts where nmap missed web services but HTTP was probed
        web_hosts = [
            h
            for h in normalized_hosts
            if h.get("web_ports_count", 0) > 0
            or (h.get("agentless_fingerprint") or {}).get("http_title")
            or (h.get("agentless_fingerprint") or {}).get("http_server")
        ]
        if not web_hosts:
            return

        # Count total web ports for info
        total_ports = sum(h.get("web_ports_count", 0) for h in web_hosts)
        budgets = {h["ip"]: self._estimate_vuln_budget_s(h) for h in web_hosts if h.get("ip")}
        remaining_budget_s = float(sum(budgets.values()))

        self.current_phase = "vulns"
        self._set_ui_detail("web vuln scan")
        self.ui.print_status(self.ui.t("vuln_analysis", len(web_hosts)), "HEADER")
        workers = min(3, self.config["threads"])
        workers = max(1, int(workers))

        # Try to use rich for progress visualization
        try:
            from rich.progress import Progress

            use_rich = True
        except ImportError:
            use_rich = False

        # Keep output quiet from the moment worker threads start.
        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self.scan_vulnerabilities_web, h): h["ip"] for h in web_hosts
                }

                total = len(futures)
                done = 0
                start_t = time.time()

                if use_rich and total > 0:
                    # Rich progress bar for vulnerability scanning (quiet UI + timeout-aware upper bound ETA)
                    with Progress(
                        *self._progress_columns(
                            show_detail=True,
                            show_eta=True,
                            show_elapsed=True,
                        ),
                        console=self._progress_console(),
                        refresh_per_second=4,
                    ) as progress:
                        eta_upper_init = self._format_eta(remaining_budget_s / workers)
                        initial_detail = self._get_ui_detail()
                        task = progress.add_task(
                            f"[cyan]Vuln scan ({total_ports} ports)",
                            total=total,
                            eta_upper=eta_upper_init,
                            eta_est="",
                            detail=initial_detail,
                        )
                        pending = set(futures)
                        last_detail = initial_detail
                        while pending:
                            if self.interrupted:
                                for pending_fut in pending:
                                    pending_fut.cancel()
                                break

                            completed, pending = wait(
                                pending, timeout=0.25, return_when=FIRST_COMPLETED
                            )
                            detail = self._get_ui_detail()
                            if detail != last_detail:
                                progress.update(task, detail=detail)
                                last_detail = detail

                            for fut in completed:
                                host_ip = futures[fut]
                                try:
                                    res = fut.result()
                                    if res:
                                        self.results["vulnerabilities"].append(res)
                                        vuln_count = len(res.get("vulnerabilities", []))
                                        if vuln_count > 0 and self.logger:
                                            self.logger.info(
                                                "Vulnerabilities recorded on %s", res["host"]
                                            )
                                except Exception as exc:
                                    self.logger.error("Vuln worker error for %s: %s", host_ip, exc)
                                    self.logger.debug(
                                        "Vuln worker exception details for %s",
                                        host_ip,
                                        exc_info=True,
                                    )
                                done += 1
                                remaining_budget_s = max(
                                    0.0, remaining_budget_s - budgets.get(host_ip, 0.0)
                                )
                                remaining = max(0, total - done)
                                elapsed_s = max(0.001, time.time() - start_t)
                                rate = done / elapsed_s if done else 0.0
                                eta_est_val = (
                                    self._format_eta(remaining / rate)
                                    if rate > 0.0 and remaining
                                    else ""
                                )
                                progress.update(
                                    task,
                                    advance=1,
                                    description=f"[cyan]{self.ui.t('scanned_host', host_ip)}",
                                    eta_upper=self._format_eta(remaining_budget_s / workers),
                                    eta_est=f"ETA≈ {eta_est_val}" if eta_est_val else "",
                                    detail=last_detail,
                                )
                else:
                    # Fallback without rich (throttled)
                    for fut in as_completed(futures):
                        if self.interrupted:
                            for pending_fut in futures:
                                pending_fut.cancel()
                            break
                        host_ip = futures[fut]
                        try:
                            res = fut.result()
                            if res:
                                self.results["vulnerabilities"].append(res)
                        except Exception as exc:
                            self.ui.print_status(
                                self.ui.t("worker_error", exc), "WARNING", force=True
                            )
                            if self.logger:
                                self.logger.debug(
                                    "Vuln worker exception details for %s", host_ip, exc_info=True
                                )
                        done += 1
                        remaining_budget_s = max(
                            0.0, remaining_budget_s - budgets.get(host_ip, 0.0)
                        )
                        if total and done % max(1, total // 10) == 0:
                            self.ui.print_status(
                                f"{self.ui.t('progress', done, total)} | ETA≤ {self._format_eta(remaining_budget_s / workers)}",
                                "INFO",
                                update_activity=False,
                                force=True,
                            )
