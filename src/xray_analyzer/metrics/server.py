"""Prometheus metrics HTTP server for xray-analyzer censorship scan results.

Exposes /metrics in Prometheus text format (0.0.4) and /health for liveness checks.
No external prometheus-client library required — writes the text format directly.
"""

import time
from dataclasses import dataclass

from aiohttp import web

from xray_analyzer.core.logger import get_logger
from xray_analyzer.diagnostics.censor_checker import CensorCheckSummary, DomainStatus

log = get_logger("metrics")


def _esc(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass
class MetricsState:
    """Holds the latest scan results for the metrics endpoint.

    Updated after every scan completion; read by the HTTP handler.
    Both operations happen in the same asyncio event loop so no locking is needed.
    """

    summary: CensorCheckSummary | None = None
    last_run: float = 0.0
    scan_duration: float = 0.0
    scan_error: str = ""

    # Set once at startup so the /metrics labels show what is being monitored
    proxy_label: str = "direct"
    domain_count: int = 0

    def update(self, summary: CensorCheckSummary, duration: float) -> None:
        self.summary = summary
        self.last_run = time.time()
        self.scan_duration = duration
        self.scan_error = ""
        self.proxy_label = _esc(summary.proxy_url) if summary.proxy_url else "direct"

    def mark_error(self, error: str) -> None:
        self.scan_error = error
        self.last_run = time.time()

    # ------------------------------------------------------------------
    # Prometheus text rendering
    # ------------------------------------------------------------------

    def render(self) -> str:
        lines: list[str] = []

        proxy = self.proxy_label

        if self.summary is None:
            # Server started but no scan has completed yet
            lines.append("# xray-analyzer metrics: waiting for first scan")
            lines.append(f'xray_scan_up{{proxy="{proxy}"}} 0')
            return "\n".join(lines) + "\n"

        s = self.summary

        # ---- per-domain accessibility --------------------------------
        lines += [
            "# HELP xray_domain_accessible Domain reachability: 1=OK, 0=blocked, 0.5=partial",
            "# TYPE xray_domain_accessible gauge",
        ]
        for r in s.results:
            value = 1.0 if r.status == DomainStatus.OK else (0.5 if r.status == DomainStatus.PARTIAL else 0.0)
            bt = _esc(r.block_type or "")
            d = _esc(r.domain)
            lines.append(
                f'xray_domain_accessible{{domain="{d}",status="{r.status}",block_type="{bt}",proxy="{proxy}"}} {value}'
            )

        # ---- per-domain HTTP codes ------------------------------------
        lines += [
            "",
            "# HELP xray_domain_http_code HTTP status code from domain check (0 = no response / timeout)",
            "# TYPE xray_domain_http_code gauge",
        ]
        for r in s.results:
            d = _esc(r.domain)
            lines.append(f'xray_domain_http_code{{domain="{d}",scheme="http",proxy="{proxy}"}} {r.http_code}')
            lines.append(f'xray_domain_http_code{{domain="{d}",scheme="https",proxy="{proxy}"}} {r.https_code}')

        # ---- per-domain TLS validity ---------------------------------
        lines += [
            "",
            "# HELP xray_domain_tls_valid TLS certificate validity (1=valid, 0=invalid or absent)",
            "# TYPE xray_domain_tls_valid gauge",
        ]
        for r in s.results:
            v = 1 if r.tls_valid else 0
            lines.append(f'xray_domain_tls_valid{{domain="{_esc(r.domain)}",proxy="{proxy}"}} {v}')

        # ---- per-domain DPI detection --------------------------------
        lines += [
            "",
            "# HELP xray_domain_dpi_detected DPI signatures detected (1=yes, 0=no) — domain may still be accessible",
            "# TYPE xray_domain_dpi_detected gauge",
        ]
        for r in s.results:
            v = 1 if r.details.get("dpi_detected") else 0
            lines.append(f'xray_domain_dpi_detected{{domain="{_esc(r.domain)}",proxy="{proxy}"}} {v}')

        # ---- scan summary counters -----------------------------------
        lines += [
            "",
            "# HELP xray_scan_domains_total Total domains checked in last scan",
            "# TYPE xray_scan_domains_total gauge",
            f'xray_scan_domains_total{{proxy="{proxy}"}} {s.total}',
            "",
            "# HELP xray_scan_domains_ok Accessible (OK) domains in last scan",
            "# TYPE xray_scan_domains_ok gauge",
            f'xray_scan_domains_ok{{proxy="{proxy}"}} {s.ok}',
            "",
            "# HELP xray_scan_domains_blocked Blocked domains in last scan",
            "# TYPE xray_scan_domains_blocked gauge",
            f'xray_scan_domains_blocked{{proxy="{proxy}"}} {s.blocked}',
            "",
            "# HELP xray_scan_domains_partial Partially accessible domains in last scan",
            "# TYPE xray_scan_domains_partial gauge",
            f'xray_scan_domains_partial{{proxy="{proxy}"}} {s.partial}',
        ]

        # ---- scan timing & health ------------------------------------
        lines += [
            "",
            "# HELP xray_scan_last_run_timestamp_seconds Unix timestamp of last completed scan",
            "# TYPE xray_scan_last_run_timestamp_seconds gauge",
            f'xray_scan_last_run_timestamp_seconds{{proxy="{proxy}"}} {self.last_run:.3f}',
            "",
            "# HELP xray_scan_duration_seconds Duration of last scan in seconds",
            "# TYPE xray_scan_duration_seconds gauge",
            f'xray_scan_duration_seconds{{proxy="{proxy}"}} {self.scan_duration:.3f}',
            "",
            "# HELP xray_scan_up 1 if last scan succeeded, 0 if it errored",
            "# TYPE xray_scan_up gauge",
            f'xray_scan_up{{proxy="{proxy}"}} {0 if self.scan_error else 1}',
        ]

        return "\n".join(lines) + "\n"


async def run_metrics_server(host: str, port: int, state: MetricsState) -> web.AppRunner:
    """Start the Prometheus HTTP server.  Returns the AppRunner so the caller can clean up."""

    async def handle_metrics(_request: web.Request) -> web.Response:
        return web.Response(
            text=state.render(),
            headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
        )

    async def handle_health(_request: web.Request) -> web.Response:
        if state.summary is None and not state.scan_error:
            return web.Response(status=503, text="waiting for first scan\n")
        if state.scan_error:
            return web.Response(status=500, text=f"last scan failed: {state.scan_error}\n")
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
