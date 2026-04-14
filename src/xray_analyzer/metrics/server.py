"""Prometheus metrics HTTP server for xray-analyzer censorship scan results.

Exposes /metrics in Prometheus text format (0.0.4) and /health for liveness checks.
No external prometheus-client library required — writes the text format directly.
"""

import time
from dataclasses import dataclass, field

from aiohttp import web

from xray_analyzer.core.logger import get_logger
from xray_analyzer.diagnostics.censor_checker import CensorCheckSummary, DomainStatus

log = get_logger("metrics")


def _esc(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass
class ProxyScanEntry:
    """Scan results for a single proxy."""

    summary: CensorCheckSummary | None = None
    last_run: float = 0.0
    scan_duration: float = 0.0
    scan_error: str = ""


@dataclass
class MetricsState:
    """Holds the latest scan results for the metrics endpoint.

    Supports multiple proxies — each identified by a label string.
    Updated after every scan completion; read by the HTTP handler.
    Both operations happen in the same asyncio event loop so no locking is needed.
    """

    domain_count: int = 0
    _entries: dict[str, ProxyScanEntry] = field(default_factory=dict)

    def register_proxy(self, label: str) -> None:
        """Pre-register a proxy label so it appears in metrics before first scan."""
        if label not in self._entries:
            self._entries[label] = ProxyScanEntry()

    def update(self, summary: CensorCheckSummary, duration: float, proxy_label: str | None = None) -> None:
        label = proxy_label or (_esc(summary.proxy_url) if summary.proxy_url else "direct")
        if label not in self._entries:
            self._entries[label] = ProxyScanEntry()
        e = self._entries[label]
        e.summary = summary
        e.last_run = time.time()
        e.scan_duration = duration
        e.scan_error = ""

    def mark_error(self, error: str, proxy_label: str = "direct") -> None:
        if proxy_label not in self._entries:
            self._entries[proxy_label] = ProxyScanEntry()
        e = self._entries[proxy_label]
        e.scan_error = error
        e.last_run = time.time()

    @property
    def _all_entries(self) -> list[tuple[str, ProxyScanEntry]]:
        return list(self._entries.items())

    @property
    def has_any_scan(self) -> bool:
        return any(e.summary is not None for _, e in self._all_entries)

    @property
    def has_any_error(self) -> bool:
        return any(e.scan_error for _, e in self._all_entries)

    # ------------------------------------------------------------------
    # Prometheus text rendering
    # ------------------------------------------------------------------

    def render(self) -> str:
        entries = self._all_entries

        if not entries:
            lines = [
                "# xray-analyzer metrics: no proxies registered",
                'xray_scan_up{proxy="direct"} 0',
            ]
            return "\n".join(lines) + "\n"

        # Any entry with no completed scan yet?
        if not self.has_any_scan:
            lines = ["# xray-analyzer metrics: waiting for first scan"]
            for label, _ in entries:
                lines.append(f'xray_scan_up{{proxy="{_esc(label)}"}} 0')
            return "\n".join(lines) + "\n"

        lines: list[str] = []

        # ---- per-domain accessibility --------------------------------
        lines += [
            "# HELP xray_domain_accessible Domain reachability: 1=OK, 0=blocked, 0.5=partial",
            "# TYPE xray_domain_accessible gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            proxy = _esc(label)
            for r in e.summary.results:
                value = 1.0 if r.status == DomainStatus.OK else (0.5 if r.status == DomainStatus.PARTIAL else 0.0)
                bt = _esc(r.block_type or "")
                d = _esc(r.domain)
                st = r.status
                lines.append(
                    f'xray_domain_accessible{{domain="{d}",status="{st}",block_type="{bt}",proxy="{proxy}"}} {value}'
                )

        # ---- per-domain HTTP codes ------------------------------------
        lines += [
            "",
            "# HELP xray_domain_http_code HTTP status code from domain check (0 = no response / timeout)",
            "# TYPE xray_domain_http_code gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            proxy = _esc(label)
            for r in e.summary.results:
                d = _esc(r.domain)
                lines.append(f'xray_domain_http_code{{domain="{d}",scheme="http",proxy="{proxy}"}} {r.http_code}')
                lines.append(f'xray_domain_http_code{{domain="{d}",scheme="https",proxy="{proxy}"}} {r.https_code}')

        # ---- per-domain TLS validity ---------------------------------
        lines += [
            "",
            "# HELP xray_domain_tls_valid TLS certificate validity (1=valid, 0=invalid or absent)",
            "# TYPE xray_domain_tls_valid gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            proxy = _esc(label)
            for r in e.summary.results:
                v = 1 if r.tls_valid else 0
                lines.append(f'xray_domain_tls_valid{{domain="{_esc(r.domain)}",proxy="{proxy}"}} {v}')

        # ---- per-domain DPI detection --------------------------------
        lines += [
            "",
            "# HELP xray_domain_dpi_detected DPI signatures detected (1=yes, 0=no) — domain may still be accessible",
            "# TYPE xray_domain_dpi_detected gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            proxy = _esc(label)
            for r in e.summary.results:
                v = 1 if r.details.get("dpi_detected") else 0
                lines.append(f'xray_domain_dpi_detected{{domain="{_esc(r.domain)}",proxy="{proxy}"}} {v}')

        # ---- scan summary counters -----------------------------------
        lines += [
            "",
            "# HELP xray_scan_domains_total Total domains checked in last scan",
            "# TYPE xray_scan_domains_total gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            lines.append(f'xray_scan_domains_total{{proxy="{_esc(label)}"}} {e.summary.total}')

        lines += [
            "",
            "# HELP xray_scan_domains_ok Accessible (OK) domains in last scan",
            "# TYPE xray_scan_domains_ok gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            lines.append(f'xray_scan_domains_ok{{proxy="{_esc(label)}"}} {e.summary.ok}')

        lines += [
            "",
            "# HELP xray_scan_domains_blocked Blocked domains in last scan",
            "# TYPE xray_scan_domains_blocked gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            lines.append(f'xray_scan_domains_blocked{{proxy="{_esc(label)}"}} {e.summary.blocked}')

        lines += [
            "",
            "# HELP xray_scan_domains_partial Partially accessible domains in last scan",
            "# TYPE xray_scan_domains_partial gauge",
        ]
        for label, e in entries:
            if e.summary is None:
                continue
            lines.append(f'xray_scan_domains_partial{{proxy="{_esc(label)}"}} {e.summary.partial}')

        # ---- scan timing & health ------------------------------------
        lines += [
            "",
            "# HELP xray_scan_last_run_timestamp_seconds Unix timestamp of last completed scan",
            "# TYPE xray_scan_last_run_timestamp_seconds gauge",
        ]
        for label, e in entries:
            if e.last_run:
                lines.append(f'xray_scan_last_run_timestamp_seconds{{proxy="{_esc(label)}"}} {e.last_run:.3f}')

        lines += [
            "",
            "# HELP xray_scan_duration_seconds Duration of last scan in seconds",
            "# TYPE xray_scan_duration_seconds gauge",
        ]
        for label, e in entries:
            if e.summary is not None:
                lines.append(f'xray_scan_duration_seconds{{proxy="{_esc(label)}"}} {e.scan_duration:.3f}')

        lines += [
            "",
            "# HELP xray_scan_up 1 if last scan succeeded, 0 if it errored",
            "# TYPE xray_scan_up gauge",
        ]
        for label, e in entries:
            up = 0 if e.scan_error else (1 if e.summary is not None else 0)
            lines.append(f'xray_scan_up{{proxy="{_esc(label)}"}} {up}')

        return "\n".join(lines) + "\n"


async def run_metrics_server(host: str, port: int, state: MetricsState) -> web.AppRunner:
    """Start the Prometheus HTTP server.  Returns the AppRunner so the caller can clean up."""

    async def handle_metrics(_request: web.Request) -> web.Response:
        return web.Response(
            text=state.render(),
            headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
        )

    async def handle_health(_request: web.Request) -> web.Response:
        if not state.has_any_scan and not state.has_any_error:
            return web.Response(status=503, text="waiting for first scan\n")
        if state.has_any_error and not state.has_any_scan:
            return web.Response(status=500, text="last scan failed\n")
        return web.Response(text="OK\n")

    app = web.Application()
    app.router.add_get("/metrics", handle_metrics)
    app.router.add_get("/health", handle_health)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    log.info("Metrics server started", host=host, port=port)
    return runner
