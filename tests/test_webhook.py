#!/usr/bin/env python3
"""
RedAudit - Tests for webhook helpers.
"""

from redaudit.utils import webhook


def test_extract_cve_ids_from_multiple_sources():
    finding = {
        "cve_ids": ["cve-2020-1234", "CVE-2020-1234", "  "],
        "descriptive_title": "Issue CVE-2021-0001 detected",
        "url": "https://example.com/CVE-2022-9999",
        "nikto_findings": ["CVE-2019-0001: test"],
        "testssl_analysis": {
            "summary": "CVE-2018-12345 present",
            "vulnerabilities": ["CVE-2017-7654 weak cipher"],
        },
    }

    cves = webhook._extract_cve_ids(finding)
    assert cves == [
        "CVE-2017-7654",
        "CVE-2018-12345",
        "CVE-2019-0001",
        "CVE-2020-1234",
        "CVE-2021-0001",
        "CVE-2022-9999",
    ]


def test_build_alert_payload_includes_details():
    finding = {
        "severity": "High",
        "descriptive_title": "Example issue",
        "category": "web",
        "url": "https://example.com",
        "port": 443,
        "nikto_findings": ["a", "b", "c", "d"],
        "testssl_analysis": {"summary": "TLS weak"},
        "cve_ids": ["CVE-2020-1234"],
    }

    payload = webhook.build_alert_payload(finding, host="10.0.0.1", scan_target="10.0.0.0/24")
    assert payload["alert"]["severity"] == "HIGH"
    assert payload["alert"]["host"] == "10.0.0.1"
    assert payload["alert"]["title"] == "Example issue"
    assert payload["details"]["nikto_count"] == 4
    assert payload["details"]["nikto_sample"] == ["a", "b", "c"]
    assert payload["details"]["testssl"] == "TLS weak"
    assert payload["details"]["cves"] == ["CVE-2020-1234"]


def test_send_webhook_skips_without_url():
    assert webhook.send_webhook("", {"a": 1}) is False


def test_send_webhook_success(monkeypatch):
    class _Response:
        ok = True
        status_code = 200
        reason = "OK"
        text = "ok"

    class _Requests:
        class exceptions:
            Timeout = type("Timeout", (Exception,), {})
            RequestException = type("RequestException", (Exception,), {})

        def __init__(self):
            self.calls = []

        def post(self, url, json, headers, timeout):
            self.calls.append((url, json, headers, timeout))
            return _Response()

    dummy = _Requests()
    monkeypatch.setattr(webhook, "REQUESTS_AVAILABLE", True)
    monkeypatch.setattr(webhook, "requests", dummy)

    payload = {"k": "v"}
    assert webhook.send_webhook("https://example.com", payload, timeout=5) is True
    assert dummy.calls
    url, sent_payload, headers, timeout = dummy.calls[0]
    assert url == "https://example.com"
    assert sent_payload == payload
    assert headers["Content-Type"] == "application/json"
    assert timeout == 5


def test_send_webhook_requests_unavailable(monkeypatch):
    monkeypatch.setattr(webhook, "REQUESTS_AVAILABLE", False)
    monkeypatch.setattr(webhook, "requests", None)
    assert webhook.send_webhook("https://example.com", {"a": 1}) is False


def test_send_webhook_non_ok(monkeypatch):
    class _Response:
        ok = False
        status_code = 400
        reason = "Bad"
        text = "bad request"

    class _Requests:
        class exceptions:
            Timeout = type("Timeout", (Exception,), {})
            RequestException = type("RequestException", (Exception,), {})

        def post(self, *_args, **_kwargs):
            return _Response()

    dummy = _Requests()
    monkeypatch.setattr(webhook, "REQUESTS_AVAILABLE", True)
    monkeypatch.setattr(webhook, "requests", dummy)

    assert webhook.send_webhook("https://example.com", {"a": 1}) is False


def test_send_webhook_timeout(monkeypatch):
    class _Requests:
        class exceptions:
            Timeout = type("Timeout", (Exception,), {})
            RequestException = type("RequestException", (Exception,), {})

        def post(self, *_args, **_kwargs):
            raise _Requests.exceptions.Timeout()

    dummy = _Requests()
    monkeypatch.setattr(webhook, "REQUESTS_AVAILABLE", True)
    monkeypatch.setattr(webhook, "requests", dummy)

    assert webhook.send_webhook("https://example.com", {"a": 1}) is False


def test_send_webhook_request_exception(monkeypatch):
    class _Requests:
        class exceptions:
            Timeout = type("Timeout", (Exception,), {})
            RequestException = type("RequestException", (Exception,), {})

        def post(self, *_args, **_kwargs):
            raise _Requests.exceptions.RequestException("boom")

    dummy = _Requests()
    monkeypatch.setattr(webhook, "REQUESTS_AVAILABLE", True)
    monkeypatch.setattr(webhook, "requests", dummy)

    assert webhook.send_webhook("https://example.com", {"a": 1}) is False


def test_process_findings_for_alerts_counts_sent(monkeypatch):
    results = {
        "vulnerabilities": [
            {
                "host": "10.0.0.1",
                "vulnerabilities": [
                    {"severity": "high", "descriptive_title": "one"},
                    {"severity": "low", "descriptive_title": "two"},
                ],
            },
            {"host": "10.0.0.2", "vulnerabilities": [{"severity": "critical"}]},
        ]
    }

    sent = []

    def _send(_url, _payload, **_kwargs):
        sent.append(_payload)
        return True

    monkeypatch.setattr(webhook, "send_webhook", _send)

    count = webhook.process_findings_for_alerts(
        results,
        webhook_url="https://example.com",
        config={"target_networks": ["10.0.0.0/24"], "scan_mode": "normal"},
    )
    assert count == 2
    assert len(sent) == 2
