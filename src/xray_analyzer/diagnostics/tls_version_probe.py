"""Forced-TLS-version probe (1.2 / 1.3 / default).

DPI boxes frequently treat TLS 1.2 and 1.3 differently — a host that succeeds
on 1.3 may fail on 1.2 with a handshake alert, or vice-versa. Running both
versions separately exposes this asymmetry.

On top of the TLS side of things the probe also flags ISP splash pages:
  - HTTP 451 (Unavailable For Legal Reasons)
  - Redirect to a different registrable domain
  - Resolved IP ∈ harvested stub_ips (passed in from dns_dpi_prober)
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Final
from urllib.parse import urlparse

import aiohttp

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import DiagnosticResult
from xray_analyzer.diagnostics.error_classifier import ErrorLabel, classify, label_to_status

log = get_logger("tls_version_probe")

_USER_AGENT: Final[str] = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)


def _make_ssl_context(forced_version: ssl.TLSVersion | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # We're probing DPI behaviour, not validating authenticity — a cert error
    # is a useful signal (TLS_MITM) that error_classifier catches.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if forced_version is not None:
        ctx.minimum_version = forced_version
        ctx.maximum_version = forced_version
    return ctx


def _version_label(forced_version: ssl.TLSVersion | None) -> str:
    if forced_version is ssl.TLSVersion.TLSv1_2:
        return "TLS 1.2"
    if forced_version is ssl.TLSVersion.TLSv1_3:
        return "TLS 1.3"
    return "TLS"


def evaluate_response(
    response_status: int,
    location: str,
    target_host: str,
    resolved_ip: str | None,
    stub_ips: set[str] | None,
) -> tuple[ErrorLabel, str]:
    """Turn a completed HTTP(S) response into an (ErrorLabel, detail) tuple.

    Exposed (not private) so both `tls_version_probe` and `http_injection_probe`
    share the same redirect / ISP-page logic.
    """
    if stub_ips and resolved_ip and resolved_ip in stub_ips:
        return ErrorLabel.ISP_PAGE, f"resolved to stub IP {resolved_ip}"

    if response_status == 451:
        return ErrorLabel.ISP_PAGE, "HTTP 451 legal block"

    if 300 <= response_status < 400 and location:
        try:
            parsed = urlparse(location if location.startswith("http") else f"https://{location}")
            loc_host = (parsed.netloc or "").lower().split(":")[0]
        except Exception:  # malformed Location
            loc_host = ""
        norm_loc = loc_host.removeprefix("www.")
        norm_tgt = target_host.lower().removeprefix("www.")
        if norm_loc and norm_loc != norm_tgt and not norm_loc.endswith("." + norm_tgt):
            return ErrorLabel.ISP_PAGE, f"cross-domain redirect → {loc_host}"

    # Everything from 2xx through "same-domain 3xx" and even 5xx is "reachable".
    # 5xx is usually upstream — not a DPI signal — but still counts as probe OK.
    return ErrorLabel.OK, f"HTTP {response_status}"


async def probe_tls(
    domain: str,
    *,
    forced_version: ssl.TLSVersion | None = None,
    port: int = 443,
    stub_ips: set[str] | None = None,
    timeout: float = 10.0,
    resolved_ip: str | None = None,
) -> DiagnosticResult:
    """Probe HTTPS with an optional clamped TLS version."""
    check_name = _version_label(forced_version)
    ctx = _make_ssl_context(forced_version)
    url = f"https://{domain}:{port}/"
    start = asyncio.get_running_loop().time()

    try:
        timeout_cfg = aiohttp.ClientTimeout(total=timeout, connect=timeout / 2)
        async with (
            aiohttp.ClientSession(timeout=timeout_cfg) as session,
            session.get(
                url,
                headers={"User-Agent": _USER_AGENT, "Connection": "close"},
                ssl=ctx,
                allow_redirects=False,
            ) as resp,
        ):
            location = resp.headers.get("location", "")
            label, detail = evaluate_response(resp.status, location, domain, resolved_ip, stub_ips)
    except Exception as exc:
        label, detail = classify(exc)
        duration_ms = (asyncio.get_running_loop().time() - start) * 1000
        status, severity = label_to_status(label)
        log.debug(
            "TLS probe failed",
            domain=domain,
            version=check_name,
            label=label.value,
            detail=detail,
        )
        return DiagnosticResult(
            check_name=check_name,
            status=status,
            severity=severity,
            message=f"{domain}: {label.value} — {detail}",
            details={
                "domain": domain,
                "port": port,
                "tls_version": check_name,
                "label": label.value,
                "detail": detail,
            },
            duration_ms=round(duration_ms, 2),
        )

    duration_ms = (asyncio.get_running_loop().time() - start) * 1000
    status, severity = label_to_status(label)
    return DiagnosticResult(
        check_name=check_name,
        status=status,
        severity=severity,
        message=f"{domain}: {label.value} — {detail}",
        details={
            "domain": domain,
            "port": port,
            "tls_version": check_name,
            "label": label.value,
            "detail": detail,
            "http_status": None if label is ErrorLabel.ISP_PAGE and "resolved" in detail else "see detail",
        },
        duration_ms=round(duration_ms, 2),
    )
