"""Plain HTTP (port 80) probe — detects ISP splash injection and HTTP 451.

Cleartext HTTP is the easiest place for a provider to inject a redirect to
a block page, because no TLS makes it trivial. This probe fires a single
`GET http://<domain>/` and uses the shared `tls_version_probe.evaluate_response`
helper to decide ISP_PAGE vs OK.
"""

from __future__ import annotations

import asyncio

import aiohttp

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import DiagnosticResult
from xray_analyzer.diagnostics.error_classifier import classify, label_to_status
from xray_analyzer.diagnostics.tls_version_probe import evaluate_response

log = get_logger("http_injection_probe")

_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"


async def probe_http_injection(
    domain: str,
    *,
    port: int = 80,
    stub_ips: set[str] | None = None,
    timeout: float = 10.0,
    resolved_ip: str | None = None,
) -> DiagnosticResult:
    url = f"http://{domain}:{port}/"
    start = asyncio.get_running_loop().time()

    try:
        timeout_cfg = aiohttp.ClientTimeout(total=timeout, connect=timeout / 2)
        async with (
            aiohttp.ClientSession(timeout=timeout_cfg) as session,
            session.get(
                url,
                headers={"User-Agent": _USER_AGENT, "Connection": "close"},
                allow_redirects=False,
            ) as resp,
        ):
            label, detail = evaluate_response(
                resp.status,
                resp.headers.get("location", ""),
                domain,
                resolved_ip,
                stub_ips,
            )
    except Exception as exc:
        label, detail = classify(exc)

    duration_ms = (asyncio.get_running_loop().time() - start) * 1000
    status, severity = label_to_status(label)
    return DiagnosticResult(
        check_name="HTTP Injection",
        status=status,
        severity=severity,
        message=f"{domain}: {label.value} — {detail}",
        details={
            "domain": domain,
            "port": port,
            "label": label.value,
            "detail": detail,
        },
        duration_ms=round(duration_ms, 2),
    )
