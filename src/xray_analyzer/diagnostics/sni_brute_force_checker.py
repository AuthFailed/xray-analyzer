"""Whitelist-SNI brute force — find a working SNI for a blocked CDN target.

When the fat-probe reports `TCP_16_20` on a CDN IP (e.g. Hetzner), it usually
means the ISP's DPI is blocking the *SNI* we sent, not the IP. Iterating over
a curated list of Russian-whitelisted SNIs (`data/whitelist_sni.txt`: vk.com,
avito.ru, ya.ru, 2gis.ru, sberbank.ru, …) lets us find one that the DPI
leaves alone — which is exactly what you need to configure REALITY /
XTLS-Vision inbounds on your Xray server.

The first-probe RTT from the CDN scan is threaded through as `hint_rtt_ms`
so each subsequent fat-probe skips the dynamic-timeout warm-up.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.data import DATA_DIR
from xray_analyzer.diagnostics.error_classifier import ErrorLabel
from xray_analyzer.diagnostics.fat_probe_checker import fat_probe

log = get_logger("sni_brute_force")


def load_whitelist_snis(path: os.PathLike[str] | str | None = None) -> list[str]:
    """Load candidate SNIs, one per line. Empty lines and `#` comments skipped."""
    target = Path(path) if path else DATA_DIR / "whitelist_sni.txt"
    snis: list[str] = []
    with target.open(encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            snis.append(line)
    return snis


@dataclass
class SniSearchResult:
    """Outcome of a brute-force SNI search against a single IP:port."""

    target: str
    port: int
    working: list[str] = field(default_factory=list)  # SNIs that passed
    tried: int = 0
    first_working: str | None = None


async def find_working_sni(
    target: str,
    port: int = 443,
    *,
    candidates: list[str] | None = None,
    max_candidates: int = 200,
    early_exit_after: int = 1,
    max_parallel: int = 5,
    hint_rtt_ms: float | None = None,
    iterations: int = 8,  # smaller than CDN scan default — we only need "does it survive?"
    chunk_size: int = 4000,
    connect_timeout: float = 4.0,
    read_timeout: float = 6.0,
) -> SniSearchResult:
    """Try candidate SNIs until `early_exit_after` of them pass the fat-probe.

    Args:
        target:           IP or hostname to connect to.
        port:             TCP port.
        candidates:       SNIs to try. If None, loads `data/whitelist_sni.txt`.
        max_candidates:   hard cap on how many SNIs to try.
        early_exit_after: stop once this many SNIs have passed.
        max_parallel:     concurrent fat-probes. Keep small — each holds one
                          TCP socket open against the same target IP.
        hint_rtt_ms:      RTT hint forwarded to fat_probe.
    """
    if candidates is None:
        candidates = load_whitelist_snis()
    candidates = candidates[:max_candidates]

    result = SniSearchResult(target=target, port=port)
    if not candidates:
        return result

    sem = asyncio.Semaphore(max_parallel)
    stop = asyncio.Event()

    async def _try_one(sni: str) -> None:
        if stop.is_set():
            return
        async with sem:
            if stop.is_set():
                return
            probe = await fat_probe(
                target,
                port=port,
                sni=sni,
                iterations=iterations,
                chunk_size=chunk_size,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                hint_rtt_ms=hint_rtt_ms,
            )
        result.tried += 1
        if probe.label is ErrorLabel.OK:
            result.working.append(sni)
            if result.first_working is None:
                result.first_working = sni
            if len(result.working) >= early_exit_after:
                stop.set()

    tasks = [asyncio.create_task(_try_one(c)) for c in candidates]
    try:
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()

    return result


def to_diagnostic(result: SniSearchResult) -> DiagnosticResult:
    status = CheckStatus.PASS if result.first_working else CheckStatus.FAIL
    severity = CheckSeverity.INFO if result.first_working else CheckSeverity.WARNING
    if result.first_working:
        message = f"{result.target}:{result.port}: working SNI found — {result.first_working}" + (
            f" (+{len(result.working) - 1} runners-up)" if len(result.working) > 1 else ""
        )
    else:
        message = f"{result.target}:{result.port}: no working SNI in {result.tried} candidates"
    return DiagnosticResult(
        check_name="SNI Brute Force",
        status=status,
        severity=severity,
        message=message,
        details={
            "target": result.target,
            "port": result.port,
            "tried": result.tried,
            "working": result.working,
            "first_working": result.first_working,
        },
    )
