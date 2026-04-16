"""TCP 16-20 KB "fat-probe" — detects ciphertext-size DPI throttling.

Russian DPI (and increasingly others) drops connections when the encrypted
payload crosses ~16-20 KB. Our existing `proxy_rkn_throttle_checker` catches
this with a single range GET, which works but is less sensitive than a
keepalive-reused socket carrying progressively more junk through a real HTTPS
session.

Design — faithful port of `core/tcp16_scanner._fat_probe_keepalive` from
dpi-detector (MIT):

1. Open ONE aiohttp session with `TCPConnector(limit=1, force_close=False)`
   so every HEAD request reuses the same TCP socket.
2. Iteration 0 — clean `HEAD /`; measures liveness + RTT.
3. Iterations 1..N-1 — `HEAD /` with a 4 KB random `X-Pad` header, cumulative
   ciphertext grows by ~4 KB per iter. DPI drops typically trigger between
   iter 4 and iter 5 (≈16-20 KB).
4. Dynamic per-iteration read timeout = `max(rtt*3, 1.5 s)` capped by
   `fat_probe_read_timeout` — fast for fresh CDN probes, patient for slow
   paths.
5. On drop at iteration `i>0`, label as `TCP_16_20` with
   `detail="drop at ≈<i*4> KB"`. On drop at `i==0` the probe just says the
   target is down.

SNI override: when `sni` is supplied, aiohttp is pointed at the target via a
custom resolver that always maps the SNI hostname to `target`, so the TLS
handshake sends the SNI we want while the TCP socket lands at the IP we want.
"""

from __future__ import annotations

import asyncio
import random
import socket
import ssl
import string
import time
from dataclasses import dataclass

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.diagnostics.error_classifier import ErrorLabel, classify, label_to_status

log = get_logger("fat_probe_checker")

_RANDOM_POOL = "".join(random.choices(string.ascii_letters + string.digits, k=100_000))
_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"


class _PinnedResolver(AbstractResolver):
    """aiohttp resolver that always maps the queried host to a fixed IP."""

    def __init__(self, pinned_ip: str) -> None:
        self._ip = pinned_ip

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: int = socket.AF_INET,
    ) -> list[ResolveResult]:
        return [
            {
                "hostname": host,
                "host": self._ip,
                "port": port,
                "family": family,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        return None


@dataclass(frozen=True)
class FatProbeResult:
    """Raw return of `fat_probe`. Convert to `DiagnosticResult` via `to_diagnostic`."""

    alive: bool
    label: ErrorLabel
    detail: str
    drop_at_kb: int | None  # None if no drop or drop at iter 0 (host dead)
    rtt_ms: float | None  # first-iter RTT, used by sni-brute force as a hint


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def fat_probe(
    target: str,
    port: int = 443,
    *,
    sni: str | None = None,
    iterations: int = 16,
    chunk_size: int = 4000,
    connect_timeout: float = 8.0,
    read_timeout: float = 12.0,
    hint_rtt_ms: float | None = None,
) -> FatProbeResult:
    """Fat-probe `target:port`, optionally sending SNI != target.

    Args:
        target:       hostname OR IP to connect to.
        port:         TCP port (80 or 443).
        sni:          SNI to present in the TLS handshake. If None, `target`
                      is used as-is (works for hostname targets). If set and
                      `target` looks like an IP, aiohttp will resolve `sni`
                      via a pinned resolver back to `target`.
        iterations:   total number of HEAD requests (>=2).
        chunk_size:   bytes of X-Pad junk header per iteration 1..N-1.
        connect_timeout / read_timeout: aiohttp timeouts. `read_timeout` is
                      the hard cap; actual per-iter timeout is dynamic.
        hint_rtt_ms:  optional pre-measured RTT (ms). Skips the warm-up phase
                      — lets sni-brute-force probes reuse the first probe's RTT.
    """
    scheme = "http" if port == 80 else "https"
    # URL host = SNI when provided, else the raw target.
    url_host = sni if sni else target
    url = f"{scheme}://{url_host}:{port}/"

    needs_pinning = sni is not None and sni != target
    connector = aiohttp.TCPConnector(
        limit=1,
        force_close=False,
        resolver=_PinnedResolver(target) if needs_pinning else None,
        ssl=_make_ssl_context() if scheme == "https" else False,
    )

    session_timeout = aiohttp.ClientTimeout(
        total=None,  # per-request timeout wins
        connect=connect_timeout,
    )

    rtt_measurements: list[float] = []
    dynamic_timeout: float | None = max((hint_rtt_ms or 0) / 1000 * 3.0, 1.5) if hint_rtt_ms else None
    if dynamic_timeout is not None:
        dynamic_timeout = min(dynamic_timeout, read_timeout)

    alive = False
    try:
        async with aiohttp.ClientSession(connector=connector, timeout=session_timeout) as session:
            for i in range(iterations):
                headers = {"User-Agent": _USER_AGENT, "Connection": "keep-alive"}
                if i > 0:
                    start_idx = random.randint(0, len(_RANDOM_POOL) - chunk_size - 1)
                    headers["X-Pad"] = _RANDOM_POOL[start_idx : start_idx + chunk_size]

                per_iter_read = dynamic_timeout if dynamic_timeout is not None else read_timeout
                req_timeout = aiohttp.ClientTimeout(
                    total=per_iter_read + connect_timeout,
                    connect=connect_timeout,
                    sock_read=per_iter_read,
                )

                t0 = time.monotonic()
                try:
                    async with session.head(url, headers=headers, timeout=req_timeout, allow_redirects=False) as _resp:
                        pass
                except Exception as exc:
                    label, detail = classify(exc)
                    if i == 0:
                        return FatProbeResult(
                            alive=False,
                            label=label,
                            detail=detail,
                            drop_at_kb=None,
                            rtt_ms=None,
                        )
                    # drop mid-stream — elevate to TCP_16_20 when the drop falls
                    # inside the classic fat-probe window; otherwise keep the
                    # underlying label but add the iteration number.
                    drop_kb = round(i * chunk_size / 1024)
                    final_label = ErrorLabel.TCP_16_20 if 1 <= drop_kb <= 30 else label
                    return FatProbeResult(
                        alive=True,
                        label=final_label,
                        detail=f"{detail} at ≈{drop_kb} KB",
                        drop_at_kb=drop_kb,
                        rtt_ms=rtt_measurements[0] * 1000 if rtt_measurements else None,
                    )

                elapsed = time.monotonic() - t0
                if i == 0:
                    alive = True
                if hint_rtt_ms is None and i < 2:
                    rtt_measurements.append(elapsed)
                    if len(rtt_measurements) == 2:
                        base_rtt = max(rtt_measurements)
                        dynamic_timeout = min(max(base_rtt * 3.0, 1.5), read_timeout)

                await asyncio.sleep(0.05)
    finally:
        await connector.close()

    return FatProbeResult(
        alive=alive,
        label=ErrorLabel.OK,
        detail=f"survived {iterations} iterations",
        drop_at_kb=None,
        rtt_ms=rtt_measurements[0] * 1000 if rtt_measurements else None,
    )


def to_diagnostic(result: FatProbeResult, target: str, port: int, sni: str | None) -> DiagnosticResult:
    """Convert a FatProbeResult to the standard DiagnosticResult shape."""
    if result.label is ErrorLabel.OK:
        status, severity = CheckStatus.PASS, CheckSeverity.INFO
        message = f"{target}:{port}: no throttle detected"
    else:
        status, severity = label_to_status(result.label)
        message = f"{target}:{port}: {result.label.value} — {result.detail}"

    return DiagnosticResult(
        check_name="TCP 16-20 KB Fat Probe",
        status=status,
        severity=severity,
        message=message,
        details={
            "target": target,
            "port": port,
            "sni": sni,
            "alive": result.alive,
            "label": result.label.value,
            "detail": result.detail,
            "drop_at_kb": result.drop_at_kb,
            "rtt_ms": round(result.rtt_ms, 2) if result.rtt_ms else None,
        },
    )


async def check_fat_probe(
    target: str,
    port: int = 443,
    *,
    sni: str | None = None,
    iterations: int = 16,
    chunk_size: int = 4000,
    connect_timeout: float = 8.0,
    read_timeout: float = 12.0,
    hint_rtt_ms: float | None = None,
) -> DiagnosticResult:
    """Convenience: fat_probe + to_diagnostic in one call."""
    result = await fat_probe(
        target,
        port,
        sni=sni,
        iterations=iterations,
        chunk_size=chunk_size,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        hint_rtt_ms=hint_rtt_ms,
    )
    return to_diagnostic(result, target, port, sni)
