"""Telegram reachability probe — DL / UL / DC TCP ping.

Three concurrent sub-probes aggregated into one verdict:

- **Download** — streams ~30 MB from telegram.org's famous splash image; per-
  second watchdog detects stalls. Verdicts: ok / slow / stalled / blocked.
- **Upload** — POSTs 10 MB of zero-chunks to a Telegram test server on
  149.154.167.99; same stall heuristic.
- **DC ping** — raw `asyncio.open_connection` to all five Telegram datacenter
  IPs on port 443; reports RTT + reachable count.

Aggregate verdict:
  - `blocked`  — DL or UL blocked AND zero DCs reachable.
  - `slow`     — DL or UL is stalled/slow (provider is throttling, not
                 blocking outright).
  - `partial`  — some DCs unreachable but traffic still flows.
  - `ok`       — everything reachable at full speed.
  - `error`    — inconsistent / unknown.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass, field
from typing import Final

import aiohttp

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("telegram_checker")

# ── Constants ───────────────────────────────────────────────────────────────

MEDIA_URL: Final[str] = "https://telegram.org/img/Telegram200million.png"
MEDIA_SIZE_BYTES: Final[int] = int(30.97 * 1024 * 1024)  # ≈30.97 MB

TELEGRAM_DC_IPS: Final[list[tuple[str, str]]] = [
    ("149.154.175.53", "DC1"),
    ("149.154.167.51", "DC2"),
    ("149.154.175.100", "DC3"),
    ("149.154.167.91", "DC4"),
    ("91.108.56.130", "DC5"),
]
TELEGRAM_DC_PORT: Final[int] = 443

UPLOAD_TEST_IP: Final[str] = "149.154.167.99"
UPLOAD_TEST_PORT: Final[int] = 443
UPLOAD_SIZE_BYTES: Final[int] = 10 * 1024 * 1024

DEFAULT_STALL_TIMEOUT: Final[float] = 10.0
DEFAULT_TOTAL_TIMEOUT: Final[float] = 60.0
DEFAULT_DC_TIMEOUT: Final[float] = 5.0


# ── Data shape ──────────────────────────────────────────────────────────────


@dataclass
class TransferStats:
    status: str  # ok | slow | stalled | blocked | error
    bytes_total: int = 0
    duration_s: float = 0.0
    peak_bps: float = 0.0
    avg_bps: float = 0.0
    drop_at_sec: int | None = None  # when stalled: last sec we saw data


@dataclass
class DcStats:
    reachable: int = 0
    total: int = 0
    per_dc: list[dict] = field(default_factory=list)


@dataclass
class TelegramReport:
    verdict: str  # ok | slow | partial | blocked | error
    download: TransferStats
    upload: TransferStats
    dc: DcStats


# ── DC ping ─────────────────────────────────────────────────────────────────


async def _tcp_ping(ip: str, port: int, timeout: float) -> tuple[bool, float | None]:
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        rtt = time.monotonic() - t0
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True, rtt
    except Exception:
        return False, None


async def _check_dcs(dc_timeout: float = DEFAULT_DC_TIMEOUT) -> DcStats:
    async def _one(ip: str, label: str) -> dict:
        reachable, rtt = await _tcp_ping(ip, TELEGRAM_DC_PORT, dc_timeout)
        return {"ip": ip, "label": label, "reachable": reachable, "rtt_ms": rtt * 1000 if rtt else None}

    per_dc = await asyncio.gather(*[_one(ip, lbl) for ip, lbl in TELEGRAM_DC_IPS])
    reachable = sum(1 for d in per_dc if d["reachable"])
    return DcStats(reachable=reachable, total=len(TELEGRAM_DC_IPS), per_dc=per_dc)


# ── Streaming helpers (shared by DL and UL) ─────────────────────────────────


def _classify_transfer(
    total_bytes: int,
    expected_size: int,
    duration_s: float,
    last_nonzero_sec: int,
    stall_timeout: float,
) -> str:
    if total_bytes == 0:
        return "blocked"
    if total_bytes >= expected_size * 0.98:
        return "ok"
    # If we recently (< stall_timeout) saw data, we ran out of overall time
    # without a fresh stall → "slow". If the last data is older than
    # stall_timeout, the connection was dropped mid-stream → "stalled".
    if duration_s - last_nonzero_sec >= stall_timeout:
        return "stalled"
    return "slow"


async def _run_download(
    stall_timeout: float,
    total_timeout: float,
    proxy: str | None,
) -> TransferStats:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    total_bytes = 0
    peak_bps = 0.0
    t_start: float | None = None
    last_nonzero_sec = 0
    stop = asyncio.Event()

    async def _reader() -> None:
        nonlocal total_bytes, t_start, peak_bps, last_nonzero_sec
        try:
            connector = aiohttp.TCPConnector(ssl=ctx)
            async with (
                aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=total_timeout + 5),
                ) as session,
                session.get(MEDIA_URL, proxy=proxy) as resp,
            ):
                t_start = time.monotonic()
                sec_bucket_start = t_start
                sec_bytes = 0
                async for chunk in resp.content.iter_chunked(65536):
                    if stop.is_set():
                        break
                    chunk_len = len(chunk)
                    total_bytes += chunk_len
                    sec_bytes += chunk_len
                    now = time.monotonic()
                    elapsed = now - t_start
                    if now - sec_bucket_start >= 1.0:
                        peak_bps = max(peak_bps, sec_bytes / (now - sec_bucket_start))
                        if sec_bytes > 0:
                            last_nonzero_sec = int(elapsed)
                        sec_bytes = 0
                        sec_bucket_start = now
        except Exception as exc:
            log.debug("Telegram download exception", error=str(exc))

    async def _watchdog() -> None:
        nonlocal last_nonzero_sec
        while not stop.is_set():
            await asyncio.sleep(0.5)
            if t_start is None:
                continue
            elapsed = time.monotonic() - t_start
            if elapsed >= total_timeout:
                stop.set()
                return
            # stall if no byte movement for stall_timeout seconds
            if (elapsed - last_nonzero_sec) >= stall_timeout and total_bytes > 0:
                stop.set()
                return

    reader_task = asyncio.create_task(_reader())
    watchdog_task = asyncio.create_task(_watchdog())
    try:
        await asyncio.wait([reader_task, watchdog_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop.set()
        for t in (reader_task, watchdog_task):
            if not t.done():
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t

    duration = (time.monotonic() - t_start) if t_start else 0.0
    avg_bps = (total_bytes / duration) if duration > 0 else 0.0
    status = _classify_transfer(total_bytes, MEDIA_SIZE_BYTES, duration, last_nonzero_sec, stall_timeout)
    return TransferStats(
        status=status,
        bytes_total=total_bytes,
        duration_s=round(duration, 2),
        peak_bps=peak_bps,
        avg_bps=avg_bps,
        drop_at_sec=last_nonzero_sec if status == "stalled" else None,
    )


async def _run_upload(
    stall_timeout: float,
    total_timeout: float,
    proxy: str | None,
) -> TransferStats:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sent = 0
    t_start = time.monotonic()
    last_nonzero_sec = 0
    stop = asyncio.Event()

    async def _body():
        nonlocal sent, last_nonzero_sec
        chunk = b"\x00" * 16384
        while sent < UPLOAD_SIZE_BYTES and not stop.is_set():
            yield chunk
            sent += len(chunk)
            last_nonzero_sec = int(time.monotonic() - t_start)
            # let the watchdog run
            await asyncio.sleep(0)

    async def _post() -> None:
        try:
            connector = aiohttp.TCPConnector(ssl=ctx)
            async with aiohttp.ClientSession(
                connector=connector, timeout=aiohttp.ClientTimeout(total=total_timeout + 5)
            ) as session:
                url = f"https://{UPLOAD_TEST_IP}:{UPLOAD_TEST_PORT}/upload"
                async with session.post(url, data=_body(), proxy=proxy) as _resp:
                    pass
        except Exception as exc:
            log.debug("Telegram upload exception", error=str(exc))

    async def _watchdog() -> None:
        while not stop.is_set():
            await asyncio.sleep(0.5)
            elapsed = time.monotonic() - t_start
            if elapsed >= total_timeout:
                stop.set()
                return
            if (elapsed - last_nonzero_sec) >= stall_timeout and sent > 0:
                stop.set()
                return

    post_task = asyncio.create_task(_post())
    wd_task = asyncio.create_task(_watchdog())
    try:
        await asyncio.wait([post_task, wd_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop.set()
        for t in (post_task, wd_task):
            if not t.done():
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t

    duration = time.monotonic() - t_start
    avg_bps = (sent / duration) if duration > 0 else 0.0
    status = _classify_transfer(sent, UPLOAD_SIZE_BYTES, duration, last_nonzero_sec, stall_timeout)
    return TransferStats(
        status=status,
        bytes_total=sent,
        duration_s=round(duration, 2),
        peak_bps=avg_bps,  # no per-second sampling on uploads
        avg_bps=avg_bps,
        drop_at_sec=last_nonzero_sec if status == "stalled" else None,
    )


# ── Verdict + public API ────────────────────────────────────────────────────


def _overall_verdict(dl: TransferStats, ul: TransferStats, dc: DcStats) -> str:
    if (dl.status == "blocked" or ul.status == "blocked") and dc.reachable == 0:
        return "blocked"
    if dl.status in ("stalled", "slow") or ul.status in ("stalled", "slow"):
        return "slow"
    if 0 < dc.reachable < dc.total:
        return "partial"
    if dl.status == "ok" and ul.status == "ok" and dc.reachable == dc.total:
        return "ok"
    return "error"


async def check_telegram(
    *,
    proxy: str | None = None,
    stall_timeout: float = DEFAULT_STALL_TIMEOUT,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
    dc_timeout: float = DEFAULT_DC_TIMEOUT,
) -> TelegramReport:
    """Run all three Telegram probes concurrently."""
    dl, ul, dc = await asyncio.gather(
        _run_download(stall_timeout, total_timeout, proxy),
        _run_upload(stall_timeout, total_timeout, proxy),
        _check_dcs(dc_timeout),
    )
    verdict = _overall_verdict(dl, ul, dc)
    return TelegramReport(verdict=verdict, download=dl, upload=ul, dc=dc)


def to_diagnostic(report: TelegramReport) -> DiagnosticResult:
    status_by_verdict: dict[str, tuple[CheckStatus, CheckSeverity]] = {
        "ok": (CheckStatus.PASS, CheckSeverity.INFO),
        "partial": (CheckStatus.WARN, CheckSeverity.WARNING),
        "slow": (CheckStatus.WARN, CheckSeverity.WARNING),
        "blocked": (CheckStatus.FAIL, CheckSeverity.CRITICAL),
        "error": (CheckStatus.FAIL, CheckSeverity.ERROR),
    }
    status, severity = status_by_verdict[report.verdict]
    return DiagnosticResult(
        check_name="Telegram Reachability",
        status=status,
        severity=severity,
        message=(
            f"Telegram: {report.verdict} "
            f"(DL={report.download.status}, UL={report.upload.status}, "
            f"DC={report.dc.reachable}/{report.dc.total})"
        ),
        details={
            "verdict": report.verdict,
            "download": {
                "status": report.download.status,
                "bytes_total": report.download.bytes_total,
                "duration_s": report.download.duration_s,
                "avg_bps": report.download.avg_bps,
                "peak_bps": report.download.peak_bps,
                "drop_at_sec": report.download.drop_at_sec,
            },
            "upload": {
                "status": report.upload.status,
                "bytes_total": report.upload.bytes_total,
                "duration_s": report.upload.duration_s,
                "avg_bps": report.upload.avg_bps,
                "drop_at_sec": report.upload.drop_at_sec,
            },
            "dc": {
                "reachable": report.dc.reachable,
                "total": report.dc.total,
                "per_dc": report.dc.per_dc,
            },
        },
    )
