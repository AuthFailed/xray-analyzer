"""Prometheus metrics HTTP server for xray-analyzer censorship scan results.

Exposes /metrics in Prometheus text format (0.0.4) and /health for liveness checks.
No external prometheus-client library required — writes the text format directly.
"""

import time
from dataclasses import dataclass, field
from typing import Protocol

from aiohttp import web

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, HostDiagnostic
from xray_analyzer.diagnostics.cdn_target_scanner import (
    VERDICT_BLOCKED as CDN_VERDICT_BLOCKED,
)
from xray_analyzer.diagnostics.cdn_target_scanner import (
    VERDICT_OK as CDN_VERDICT_OK,
)
from xray_analyzer.diagnostics.cdn_target_scanner import (
    VERDICT_PARTIAL as CDN_VERDICT_PARTIAL,
)
from xray_analyzer.diagnostics.cdn_target_scanner import CdnScanReport
from xray_analyzer.diagnostics.censor_checker import CensorCheckSummary, DomainStatus
from xray_analyzer.diagnostics.dns_dpi_prober import (
    VERDICT_ALL_DEAD,
    VERDICT_DOH_BLOCKED,
    VERDICT_FAKE_EMPTY,
    VERDICT_FAKE_NXDOMAIN,
    VERDICT_INTERCEPT,
    VERDICT_SPOOF,
    DnsIntegrityReport,
)
from xray_analyzer.diagnostics.dns_dpi_prober import (
    VERDICT_OK as DNS_VERDICT_OK,
)
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL
from xray_analyzer.diagnostics.telegram_checker import TelegramReport

_DNS_VERDICTS: tuple[str, ...] = (
    DNS_VERDICT_OK,
    VERDICT_SPOOF,
    VERDICT_INTERCEPT,
    VERDICT_FAKE_NXDOMAIN,
    VERDICT_FAKE_EMPTY,
    VERDICT_DOH_BLOCKED,
    VERDICT_ALL_DEAD,
)
_CDN_VERDICTS: tuple[str, ...] = (CDN_VERDICT_OK, CDN_VERDICT_PARTIAL, CDN_VERDICT_BLOCKED)
_TELEGRAM_VERDICTS: tuple[str, ...] = ("ok", "slow", "partial", "blocked", "error")
_TELEGRAM_TRANSFER_STATUSES: tuple[str, ...] = ("ok", "slow", "stalled", "blocked", "error")

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
class DpiProbeState:
    """Latest DPI probe results, independent from per-proxy domain scans."""

    dns_report: DnsIntegrityReport | None = None
    dns_last_run: float = 0.0
    dns_duration: float = 0.0
    dns_error: str = ""

    cdn_report: CdnScanReport | None = None
    cdn_last_run: float = 0.0
    cdn_duration: float = 0.0
    cdn_error: str = ""

    telegram_report: TelegramReport | None = None
    telegram_last_run: float = 0.0
    telegram_duration: float = 0.0
    telegram_error: str = ""


class MetricsRenderable(Protocol):
    """Protocol for objects that can be rendered as Prometheus metrics."""

    @property
    def has_any_scan(self) -> bool: ...

    @property
    def has_any_error(self) -> bool: ...

    def render(self) -> str: ...


@dataclass
class MetricsState:
    """Holds the latest scan results for the metrics endpoint.

    Supports multiple proxies — each identified by a label string.
    Updated after every scan completion; read by the HTTP handler.
    Both operations happen in the same asyncio event loop so no locking is needed.
    """

    domain_count: int = 0
    _entries: dict[str, ProxyScanEntry] = field(default_factory=dict)
    dpi: DpiProbeState = field(default_factory=DpiProbeState)

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

    # ------------------------------------------------------------------
    # DPI probe state mutators (used by the _dpi_loop in cmd_serve)
    # ------------------------------------------------------------------

    def update_dpi_dns(self, report: DnsIntegrityReport, duration: float) -> None:
        self.dpi.dns_report = report
        self.dpi.dns_last_run = time.time()
        self.dpi.dns_duration = duration
        self.dpi.dns_error = ""

    def mark_dpi_dns_error(self, error: str) -> None:
        self.dpi.dns_error = error
        self.dpi.dns_last_run = time.time()

    def update_dpi_cdn(self, report: CdnScanReport, duration: float) -> None:
        self.dpi.cdn_report = report
        self.dpi.cdn_last_run = time.time()
        self.dpi.cdn_duration = duration
        self.dpi.cdn_error = ""

    def mark_dpi_cdn_error(self, error: str) -> None:
        self.dpi.cdn_error = error
        self.dpi.cdn_last_run = time.time()

    def update_dpi_telegram(self, report: TelegramReport, duration: float) -> None:
        self.dpi.telegram_report = report
        self.dpi.telegram_last_run = time.time()
        self.dpi.telegram_duration = duration
        self.dpi.telegram_error = ""

    def mark_dpi_telegram_error(self, error: str) -> None:
        self.dpi.telegram_error = error
        self.dpi.telegram_last_run = time.time()

    @property
    def _all_entries(self) -> list[tuple[str, ProxyScanEntry]]:
        return list(self._entries.items())

    @property
    def has_any_scan(self) -> bool:
        return any(e.summary is not None for _, e in self._all_entries)

    @property
    def has_any_error(self) -> bool:
        return any(e.scan_error for _, e in self._all_entries)

    @property
    def has_any_dpi(self) -> bool:
        """True once any DPI probe has completed or errored at least once."""
        d = self.dpi
        return d.dns_last_run > 0 or d.cdn_last_run > 0 or d.telegram_last_run > 0

    # ------------------------------------------------------------------
    # Prometheus text rendering
    # ------------------------------------------------------------------

    def render(self) -> str:
        entries = self._all_entries
        dpi_lines = self._render_dpi()

        if not entries and not dpi_lines:
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
            if dpi_lines:
                lines.append("")
                lines.extend(dpi_lines)
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

        if dpi_lines:
            lines.append("")
            lines.extend(dpi_lines)

        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # DPI probe rendering helpers
    # ------------------------------------------------------------------

    def _render_dpi(self) -> list[str]:
        """Render all DPI probe metrics. Returns empty list if no probe has run."""
        lines: list[str] = []
        lines.extend(self._render_dpi_dns())
        lines.extend(self._render_dpi_cdn())
        lines.extend(self._render_dpi_telegram())
        return lines

    def _render_dpi_dns(self) -> list[str]:
        d = self.dpi
        if d.dns_last_run == 0.0:
            return []

        lines: list[str] = []
        report = d.dns_report

        lines += [
            "# HELP xray_dpi_dns_verdict_total DNS DPI probe: domain count per verdict in last run",
            "# TYPE xray_dpi_dns_verdict_total gauge",
        ]
        for v in _DNS_VERDICTS:
            count = report.verdict_counts.get(v, 0) if report else 0
            lines.append(f'xray_dpi_dns_verdict_total{{verdict="{v}"}} {count}')

        lines += [
            "",
            "# HELP xray_dpi_dns_domain DNS DPI verdict per domain (1 = current verdict, 0 = others)",
            "# TYPE xray_dpi_dns_domain gauge",
        ]
        if report:
            for r in report.results:
                domain = _esc(str(r.details.get("domain", "")))
                current = str(r.details.get("verdict", ""))
                for v in _DNS_VERDICTS:
                    value = 1 if v == current else 0
                    lines.append(f'xray_dpi_dns_domain{{domain="{domain}",verdict="{v}"}} {value}')

        stub_count = len(report.stub_ips) if report else 0
        udp_avail = 1 if (report and report.udp_available) else 0
        doh_avail = 1 if (report and report.doh_available) else 0

        lines += [
            "",
            "# HELP xray_dpi_dns_stub_ips_total ISP stub/splash IPs harvested (appear ≥2× across UDP answers)",
            "# TYPE xray_dpi_dns_stub_ips_total gauge",
            f"xray_dpi_dns_stub_ips_total {stub_count}",
            "",
            "# HELP xray_dpi_dns_udp_available 1 if a live UDP resolver was found in the last probe",
            "# TYPE xray_dpi_dns_udp_available gauge",
            f"xray_dpi_dns_udp_available {udp_avail}",
            "",
            "# HELP xray_dpi_dns_doh_available 1 if a live DoH resolver was found in the last probe",
            "# TYPE xray_dpi_dns_doh_available gauge",
            f"xray_dpi_dns_doh_available {doh_avail}",
            "",
            "# HELP xray_dpi_dns_up 1 if last DNS DPI probe succeeded, 0 if it errored",
            "# TYPE xray_dpi_dns_up gauge",
            f"xray_dpi_dns_up {0 if d.dns_error else (1 if report is not None else 0)}",
            "",
            "# HELP xray_dpi_dns_run_duration_seconds Duration of last DNS DPI probe in seconds",
            "# TYPE xray_dpi_dns_run_duration_seconds gauge",
            f"xray_dpi_dns_run_duration_seconds {d.dns_duration:.3f}",
            "",
            "# HELP xray_dpi_dns_last_run_timestamp_seconds Unix timestamp of last DNS DPI probe",
            "# TYPE xray_dpi_dns_last_run_timestamp_seconds gauge",
            f"xray_dpi_dns_last_run_timestamp_seconds {d.dns_last_run:.3f}",
        ]
        return lines

    def _render_dpi_cdn(self) -> list[str]:
        d = self.dpi
        if d.cdn_last_run == 0.0:
            return []

        lines: list[str] = []
        report = d.cdn_report
        summaries = report.summaries if report else []

        lines += [
            "",
            "# HELP xray_dpi_cdn_provider_targets_total CDN probe: targets per provider/ASN in last run",
            "# TYPE xray_dpi_cdn_provider_targets_total gauge",
        ]
        for s in summaries:
            p, a = _esc(s.provider), _esc(s.asn)
            lines.append(f'xray_dpi_cdn_provider_targets_total{{provider="{p}",asn="{a}"}} {s.total}')

        lines += [
            "",
            "# HELP xray_dpi_cdn_provider_targets_passed CDN probe: targets passing fat-probe per provider/ASN",
            "# TYPE xray_dpi_cdn_provider_targets_passed gauge",
        ]
        for s in summaries:
            p, a = _esc(s.provider), _esc(s.asn)
            lines.append(f'xray_dpi_cdn_provider_targets_passed{{provider="{p}",asn="{a}"}} {s.passed}')

        lines += [
            "",
            "# HELP xray_dpi_cdn_provider_targets_blocked CDN probe: blocked targets per provider/ASN (16-20KB DPI)",
            "# TYPE xray_dpi_cdn_provider_targets_blocked gauge",
        ]
        for s in summaries:
            p, a = _esc(s.provider), _esc(s.asn)
            lines.append(f'xray_dpi_cdn_provider_targets_blocked{{provider="{p}",asn="{a}"}} {s.blocked}')

        lines += [
            "",
            "# HELP xray_dpi_cdn_provider_targets_errored CDN probe: targets with DNS/timeout/refused errors",
            "# TYPE xray_dpi_cdn_provider_targets_errored gauge",
        ]
        for s in summaries:
            p, a = _esc(s.provider), _esc(s.asn)
            lines.append(f'xray_dpi_cdn_provider_targets_errored{{provider="{p}",asn="{a}"}} {s.errored}')

        lines += [
            "",
            "# HELP xray_dpi_cdn_provider_verdict CDN verdict per provider/ASN (1 = current, 0 = others)",
            "# TYPE xray_dpi_cdn_provider_verdict gauge",
        ]
        for s in summaries:
            p, a = _esc(s.provider), _esc(s.asn)
            for v in _CDN_VERDICTS:
                value = 1 if s.verdict == v else 0
                lines.append(f'xray_dpi_cdn_provider_verdict{{provider="{p}",asn="{a}",verdict="{v}"}} {value}')

        lines += [
            "",
            "# HELP xray_dpi_cdn_overall_verdict Overall CDN verdict across all providers (1 = current)",
            "# TYPE xray_dpi_cdn_overall_verdict gauge",
        ]
        overall = report.overall_verdict if report else ""
        for v in _CDN_VERDICTS:
            value = 1 if overall == v else 0
            lines.append(f'xray_dpi_cdn_overall_verdict{{verdict="{v}"}} {value}')

        lines += [
            "",
            "# HELP xray_dpi_cdn_up 1 if last CDN probe succeeded, 0 if it errored",
            "# TYPE xray_dpi_cdn_up gauge",
            f"xray_dpi_cdn_up {0 if d.cdn_error else (1 if report is not None else 0)}",
            "",
            "# HELP xray_dpi_cdn_run_duration_seconds Duration of last CDN probe in seconds",
            "# TYPE xray_dpi_cdn_run_duration_seconds gauge",
            f"xray_dpi_cdn_run_duration_seconds {d.cdn_duration:.3f}",
            "",
            "# HELP xray_dpi_cdn_last_run_timestamp_seconds Unix timestamp of last CDN probe",
            "# TYPE xray_dpi_cdn_last_run_timestamp_seconds gauge",
            f"xray_dpi_cdn_last_run_timestamp_seconds {d.cdn_last_run:.3f}",
        ]
        return lines

    def _render_dpi_telegram(self) -> list[str]:
        d = self.dpi
        if d.telegram_last_run == 0.0:
            return []

        lines: list[str] = []
        report = d.telegram_report

        lines += [
            "",
            "# HELP xray_dpi_telegram_verdict Telegram overall verdict (1 = current, 0 = others)",
            "# TYPE xray_dpi_telegram_verdict gauge",
        ]
        verdict = report.verdict if report else ""
        for v in _TELEGRAM_VERDICTS:
            value = 1 if verdict == v else 0
            lines.append(f'xray_dpi_telegram_verdict{{verdict="{v}"}} {value}')

        dl_bytes = report.download.bytes_total if report else 0
        dl_dur = report.download.duration_s if report else 0.0
        dl_status = report.download.status if report else ""
        ul_bytes = report.upload.bytes_total if report else 0
        ul_dur = report.upload.duration_s if report else 0.0
        ul_status = report.upload.status if report else ""
        dc_reachable = report.dc.reachable if report else 0
        dc_total = report.dc.total if report else 0

        lines += [
            "",
            "# HELP xray_dpi_telegram_download_bytes Bytes downloaded in the last Telegram probe",
            "# TYPE xray_dpi_telegram_download_bytes gauge",
            f"xray_dpi_telegram_download_bytes {dl_bytes}",
            "",
            "# HELP xray_dpi_telegram_download_duration_seconds Duration of the last Telegram download",
            "# TYPE xray_dpi_telegram_download_duration_seconds gauge",
            f"xray_dpi_telegram_download_duration_seconds {dl_dur:.3f}",
            "",
            "# HELP xray_dpi_telegram_download_status Download status (1 = current, 0 = others)",
            "# TYPE xray_dpi_telegram_download_status gauge",
        ]
        for s in _TELEGRAM_TRANSFER_STATUSES:
            value = 1 if dl_status == s else 0
            lines.append(f'xray_dpi_telegram_download_status{{status="{s}"}} {value}')

        lines += [
            "",
            "# HELP xray_dpi_telegram_upload_bytes Bytes uploaded in the last Telegram probe",
            "# TYPE xray_dpi_telegram_upload_bytes gauge",
            f"xray_dpi_telegram_upload_bytes {ul_bytes}",
            "",
            "# HELP xray_dpi_telegram_upload_duration_seconds Duration of the last Telegram upload",
            "# TYPE xray_dpi_telegram_upload_duration_seconds gauge",
            f"xray_dpi_telegram_upload_duration_seconds {ul_dur:.3f}",
            "",
            "# HELP xray_dpi_telegram_upload_status Upload status (1 = current, 0 = others)",
            "# TYPE xray_dpi_telegram_upload_status gauge",
        ]
        for s in _TELEGRAM_TRANSFER_STATUSES:
            value = 1 if ul_status == s else 0
            lines.append(f'xray_dpi_telegram_upload_status{{status="{s}"}} {value}')

        lines += [
            "",
            "# HELP xray_dpi_telegram_dc_reachable Number of Telegram DCs reachable by TCP in the last probe",
            "# TYPE xray_dpi_telegram_dc_reachable gauge",
            f"xray_dpi_telegram_dc_reachable {dc_reachable}",
            "",
            "# HELP xray_dpi_telegram_dc_total Total number of Telegram DCs probed",
            "# TYPE xray_dpi_telegram_dc_total gauge",
            f"xray_dpi_telegram_dc_total {dc_total}",
            "",
            "# HELP xray_dpi_telegram_up 1 if last Telegram probe succeeded, 0 if it errored",
            "# TYPE xray_dpi_telegram_up gauge",
            f"xray_dpi_telegram_up {0 if d.telegram_error else (1 if report is not None else 0)}",
            "",
            "# HELP xray_dpi_telegram_run_duration_seconds Duration of last Telegram probe in seconds",
            "# TYPE xray_dpi_telegram_run_duration_seconds gauge",
            f"xray_dpi_telegram_run_duration_seconds {d.telegram_duration:.3f}",
            "",
            "# HELP xray_dpi_telegram_last_run_timestamp_seconds Unix timestamp of last Telegram probe",
            "# TYPE xray_dpi_telegram_last_run_timestamp_seconds gauge",
            f"xray_dpi_telegram_last_run_timestamp_seconds {d.telegram_last_run:.3f}",
        ]
        return lines


_STATUS_VALUE = {
    CheckStatus.PASS: 1.0,
    CheckStatus.WARN: 0.5,
    CheckStatus.FAIL: 0.0,
    CheckStatus.SKIP: -1.0,
    CheckStatus.TIMEOUT: 0.0,
}

# Check names that signal DPI when they fail with high severity.
_DPI_CHECK_KEYWORDS = ("Probe", "DPI", "Throttle")


@dataclass
class ProxyAnalysisMetricsState:
    """Holds proxy analysis results for the Prometheus metrics endpoint.

    Each proxy is identified by a label string (name or host:port).
    Updated after every analysis cycle; read by the HTTP handler.
    """

    _diagnostics: dict[str, HostDiagnostic] = field(default_factory=dict)
    _shares: dict[str, ProxyShareURL] = field(default_factory=dict)
    last_run: float = 0.0
    analysis_duration: float = 0.0
    last_error: str = ""

    def register_proxy(self, label: str, share: ProxyShareURL) -> None:
        self._shares[label] = share

    def update_proxy(self, label: str, diag: HostDiagnostic) -> None:
        self._diagnostics[label] = diag

    def finish_cycle(self, duration: float) -> None:
        self.last_run = time.time()
        self.analysis_duration = duration
        self.last_error = ""

    def mark_cycle_error(self, error: str) -> None:
        self.last_error = error
        self.last_run = time.time()

    @property
    def has_any_scan(self) -> bool:
        return bool(self._diagnostics)

    @property
    def has_any_error(self) -> bool:
        return bool(self.last_error)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _proxy_labels(self, label: str) -> str:
        """Build the common label set string for a proxy."""
        share = self._shares.get(label)
        if share:
            proxy = _esc(share.name or f"{share.server}:{share.port}")
            server = _esc(share.server)
            port = str(share.port)
            protocol = _esc(share.protocol)
        else:
            proxy = _esc(label)
            server = ""
            port = ""
            protocol = ""
        return f'proxy="{proxy}",server="{server}",port="{port}",protocol="{protocol}"'

    @staticmethod
    def _is_dpi_detected(diag: HostDiagnostic) -> bool:
        for r in diag.results:
            if (
                any(kw in r.check_name for kw in _DPI_CHECK_KEYWORDS)
                and r.status == CheckStatus.FAIL
                and r.severity in (CheckSeverity.CRITICAL, CheckSeverity.ERROR)
            ):
                return True
            if r.details.get("dpi_detected"):
                return True
        return False

    # ------------------------------------------------------------------
    # Prometheus text rendering
    # ------------------------------------------------------------------

    def render(self) -> str:
        if not self._shares and not self._diagnostics:
            return "# xray-analyzer proxy analysis: no proxies registered\nxray_proxy_analysis_up 0\n"

        if not self._diagnostics:
            lines = ["# xray-analyzer proxy analysis: waiting for first cycle"]
            for label in self._shares:
                lbl = self._proxy_labels(label)
                lines.append(f"xray_proxy_status{{{lbl}}} 0")
            lines.append("")
            lines.append("xray_proxy_analysis_up 0")
            return "\n".join(lines) + "\n"

        lines: list[str] = []

        # ---- per-proxy overall status --------------------------------
        lines += [
            "# HELP xray_proxy_status Proxy overall status: 1=pass, 0.5=warn, 0=fail",
            "# TYPE xray_proxy_status gauge",
        ]
        for label, diag in self._diagnostics.items():
            lbl = self._proxy_labels(label)
            value = _STATUS_VALUE.get(diag.overall_status, 0.0)
            lines.append(f"xray_proxy_status{{{lbl}}} {value}")

        # ---- per-proxy per-check status ------------------------------
        lines += [
            "",
            "# HELP xray_proxy_check_status Per-check status: 1=pass, 0.5=warn, 0=fail, -1=skip",
            "# TYPE xray_proxy_check_status gauge",
        ]
        for label, diag in self._diagnostics.items():
            lbl = self._proxy_labels(label)
            for r in diag.results:
                check = _esc(r.check_name)
                value = _STATUS_VALUE.get(r.status, 0.0)
                lines.append(f'xray_proxy_check_status{{{lbl},check="{check}"}} {value}')

        # ---- per-proxy per-check duration ----------------------------
        lines += [
            "",
            "# HELP xray_proxy_check_duration_ms Per-check duration in milliseconds",
            "# TYPE xray_proxy_check_duration_ms gauge",
        ]
        for label, diag in self._diagnostics.items():
            lbl = self._proxy_labels(label)
            for r in diag.results:
                if r.duration_ms > 0:
                    check = _esc(r.check_name)
                    lines.append(f'xray_proxy_check_duration_ms{{{lbl},check="{check}"}} {r.duration_ms:.1f}')

        # ---- per-proxy TCP ping latency ------------------------------
        lines += [
            "",
            "# HELP xray_proxy_ping_avg_ms TCP ping average latency in milliseconds",
            "# TYPE xray_proxy_ping_avg_ms gauge",
        ]
        for label, diag in self._diagnostics.items():
            lbl = self._proxy_labels(label)
            for r in diag.results:
                if "TCP Ping" in r.check_name and r.status == CheckStatus.PASS:
                    avg_ms = r.details.get("latency_avg_ms")
                    if avg_ms is not None:
                        lines.append(f"xray_proxy_ping_avg_ms{{{lbl}}} {avg_ms:.1f}")
                    break

        # ---- per-proxy exit IP info ----------------------------------
        lines += [
            "",
            "# HELP xray_proxy_exit_ip_info Proxy exit IP (info metric, always 1)",
            "# TYPE xray_proxy_exit_ip_info gauge",
        ]
        for label, diag in self._diagnostics.items():
            lbl = self._proxy_labels(label)
            for r in diag.results:
                if "Exit IP" in r.check_name and r.status == CheckStatus.PASS:
                    ip = _esc(r.details.get("exit_ip", ""))
                    if ip:
                        lines.append(f'xray_proxy_exit_ip_info{{{lbl},ip="{ip}"}} 1')
                    break

        # ---- per-proxy DPI detected ----------------------------------
        lines += [
            "",
            "# HELP xray_proxy_dpi_detected DPI/throttle detected on proxy path: 1=yes, 0=no",
            "# TYPE xray_proxy_dpi_detected gauge",
        ]
        for label, diag in self._diagnostics.items():
            lbl = self._proxy_labels(label)
            value = 1 if self._is_dpi_detected(diag) else 0
            lines.append(f"xray_proxy_dpi_detected{{{lbl}}} {value}")

        # ---- summary counters ----------------------------------------
        total = len(self._diagnostics)
        passing = sum(1 for d in self._diagnostics.values() if d.overall_status == CheckStatus.PASS)
        warning = sum(1 for d in self._diagnostics.values() if d.overall_status == CheckStatus.WARN)
        failing = total - passing - warning

        lines += [
            "",
            "# HELP xray_proxy_total Total proxies analyzed",
            "# TYPE xray_proxy_total gauge",
            f"xray_proxy_total {total}",
            "",
            "# HELP xray_proxy_passing Proxies with PASS status",
            "# TYPE xray_proxy_passing gauge",
            f"xray_proxy_passing {passing}",
            "",
            "# HELP xray_proxy_warning Proxies with WARN status",
            "# TYPE xray_proxy_warning gauge",
            f"xray_proxy_warning {warning}",
            "",
            "# HELP xray_proxy_failing Proxies with FAIL/TIMEOUT status",
            "# TYPE xray_proxy_failing gauge",
            f"xray_proxy_failing {failing}",
        ]

        # ---- cycle timing & health -----------------------------------
        lines += [
            "",
            "# HELP xray_proxy_analysis_duration_seconds Duration of last analysis cycle",
            "# TYPE xray_proxy_analysis_duration_seconds gauge",
            f"xray_proxy_analysis_duration_seconds {self.analysis_duration:.3f}",
            "",
            "# HELP xray_proxy_analysis_last_run_timestamp_seconds Unix timestamp of last completed cycle",
            "# TYPE xray_proxy_analysis_last_run_timestamp_seconds gauge",
            f"xray_proxy_analysis_last_run_timestamp_seconds {self.last_run:.3f}",
            "",
            "# HELP xray_proxy_analysis_up 1 if last analysis cycle succeeded, 0 if it errored",
            "# TYPE xray_proxy_analysis_up gauge",
            f"xray_proxy_analysis_up {0 if self.last_error else 1}",
        ]

        return "\n".join(lines) + "\n"


async def run_metrics_server(host: str, port: int, state: MetricsRenderable) -> web.AppRunner:
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
