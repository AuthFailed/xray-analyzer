"""Tests for Prometheus metrics rendering (xray_analyzer.metrics.server)."""

from __future__ import annotations

from collections import Counter

from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.diagnostics.cdn_target_scanner import (
    VERDICT_BLOCKED as CDN_BLOCKED,
)
from xray_analyzer.diagnostics.cdn_target_scanner import (
    VERDICT_OK as CDN_OK,
)
from xray_analyzer.diagnostics.cdn_target_scanner import (
    VERDICT_PARTIAL as CDN_PARTIAL,
)
from xray_analyzer.diagnostics.cdn_target_scanner import (
    CdnScanReport,
    ProviderSummary,
)
from xray_analyzer.diagnostics.dns_dpi_prober import (
    VERDICT_OK as DNS_OK,
)
from xray_analyzer.diagnostics.dns_dpi_prober import (
    VERDICT_SPOOF,
    DnsIntegrityReport,
)
from xray_analyzer.diagnostics.telegram_checker import (
    DcStats,
    TelegramReport,
    TransferStats,
)
from xray_analyzer.metrics.server import MetricsState


def _make_dns_result(domain: str, verdict: str) -> DiagnosticResult:
    return DiagnosticResult(
        check_name="DNS Integrity",
        status=CheckStatus.PASS if verdict == DNS_OK else CheckStatus.FAIL,
        severity=CheckSeverity.INFO if verdict == DNS_OK else CheckSeverity.CRITICAL,
        message=f"{domain}: verdict={verdict}",
        details={"domain": domain, "verdict": verdict},
    )


class TestRenderEmpty:
    def test_empty_state_says_no_proxies(self):
        out = MetricsState().render()
        assert "no proxies registered" in out
        assert 'xray_scan_up{proxy="direct"} 0' in out
        assert "xray_dpi_" not in out


class TestRenderDnsProbe:
    def test_dns_metrics_present_after_update(self):
        state = MetricsState()
        state.register_proxy("direct")
        report = DnsIntegrityReport(
            results=[
                _make_dns_result("meduza.io", VERDICT_SPOOF),
                _make_dns_result("google.com", DNS_OK),
            ],
            stub_ips={"1.2.3.4", "5.6.7.8"},
            udp_server=("1.1.1.1", "Cloudflare"),
            doh_server=("https://cloudflare-dns.com/dns-query", "Cloudflare"),
            udp_available=True,
            doh_available=True,
            verdict_counts=Counter({DNS_OK: 1, VERDICT_SPOOF: 1}),
        )
        state.update_dpi_dns(report, duration=1.5)
        out = state.render()

        assert 'xray_dpi_dns_verdict_total{verdict="ok"} 1' in out
        assert 'xray_dpi_dns_verdict_total{verdict="spoof"} 1' in out
        # verdicts never probed are still emitted as 0
        assert 'xray_dpi_dns_verdict_total{verdict="intercept"} 0' in out
        # per-domain: exactly one verdict=1 for each domain
        assert 'xray_dpi_dns_domain{domain="meduza.io",verdict="spoof"} 1' in out
        assert 'xray_dpi_dns_domain{domain="meduza.io",verdict="ok"} 0' in out
        assert 'xray_dpi_dns_domain{domain="google.com",verdict="ok"} 1' in out
        # availability and timing
        assert "xray_dpi_dns_stub_ips_total 2" in out
        assert "xray_dpi_dns_udp_available 1" in out
        assert "xray_dpi_dns_doh_available 1" in out
        assert "xray_dpi_dns_up 1" in out
        assert "xray_dpi_dns_run_duration_seconds 1.500" in out

    def test_dns_error_sets_up_to_zero(self):
        state = MetricsState()
        state.register_proxy("direct")
        state.mark_dpi_dns_error("boom")
        out = state.render()
        # error is enough to publish dns metrics with up=0
        assert "xray_dpi_dns_up 0" in out
        # no report → stub_ips=0
        assert "xray_dpi_dns_stub_ips_total 0" in out


class TestRenderCdnProbe:
    def test_cdn_summary_and_overall(self):
        state = MetricsState()
        state.register_proxy("direct")
        report = CdnScanReport(
            results=[],
            summaries=[
                ProviderSummary(
                    asn="24940", provider="Hetzner", total=5, passed=5, blocked=0, errored=0, verdict=CDN_OK
                ),
                ProviderSummary(
                    asn="13335",
                    provider="Cloudflare",
                    total=4,
                    passed=0,
                    blocked=3,
                    errored=1,
                    verdict=CDN_BLOCKED,
                ),
            ],
            overall_verdict=CDN_PARTIAL,
        )
        state.update_dpi_cdn(report, duration=3.25)
        out = state.render()

        # per-provider counters
        assert 'xray_dpi_cdn_provider_targets_total{provider="Hetzner",asn="24940"} 5' in out
        assert 'xray_dpi_cdn_provider_targets_passed{provider="Hetzner",asn="24940"} 5' in out
        assert 'xray_dpi_cdn_provider_targets_blocked{provider="Cloudflare",asn="13335"} 3' in out
        assert 'xray_dpi_cdn_provider_targets_errored{provider="Cloudflare",asn="13335"} 1' in out
        # per-provider verdict one-hot
        assert 'xray_dpi_cdn_provider_verdict{provider="Hetzner",asn="24940",verdict="ok"} 1' in out
        assert 'xray_dpi_cdn_provider_verdict{provider="Hetzner",asn="24940",verdict="blocked"} 0' in out
        assert 'xray_dpi_cdn_provider_verdict{provider="Cloudflare",asn="13335",verdict="blocked"} 1' in out
        # overall
        assert 'xray_dpi_cdn_overall_verdict{verdict="partial"} 1' in out
        assert 'xray_dpi_cdn_overall_verdict{verdict="ok"} 0' in out
        assert "xray_dpi_cdn_up 1" in out
        assert "xray_dpi_cdn_run_duration_seconds 3.250" in out


class TestRenderTelegramProbe:
    def test_telegram_verdict_and_statuses(self):
        state = MetricsState()
        state.register_proxy("direct")
        report = TelegramReport(
            verdict="slow",
            download=TransferStats(status="ok", bytes_total=31457280, duration_s=8.5, avg_bps=3.7e6, peak_bps=5.0e6),
            upload=TransferStats(status="stalled", bytes_total=1048576, duration_s=12.0, avg_bps=8.7e4, drop_at_sec=4),
            dc=DcStats(reachable=4, total=5, per_dc=[]),
        )
        state.update_dpi_telegram(report, duration=20.0)
        out = state.render()

        assert 'xray_dpi_telegram_verdict{verdict="slow"} 1' in out
        assert 'xray_dpi_telegram_verdict{verdict="ok"} 0' in out
        assert "xray_dpi_telegram_download_bytes 31457280" in out
        assert "xray_dpi_telegram_download_duration_seconds 8.500" in out
        assert 'xray_dpi_telegram_download_status{status="ok"} 1' in out
        assert 'xray_dpi_telegram_download_status{status="stalled"} 0' in out
        assert 'xray_dpi_telegram_upload_status{status="stalled"} 1' in out
        assert "xray_dpi_telegram_dc_reachable 4" in out
        assert "xray_dpi_telegram_dc_total 5" in out
        assert "xray_dpi_telegram_up 1" in out


class TestRenderDpiOnly:
    def test_dpi_only_without_any_scan(self):
        """DPI probe ran but no domain scan yet → 'waiting for first scan' + DPI block."""
        state = MetricsState()
        state.register_proxy("direct")
        state.update_dpi_telegram(
            TelegramReport(
                verdict="ok",
                download=TransferStats(status="ok", bytes_total=1, duration_s=1.0),
                upload=TransferStats(status="ok", bytes_total=1, duration_s=1.0),
                dc=DcStats(reachable=5, total=5),
            ),
            duration=5.0,
        )
        out = state.render()
        assert "waiting for first scan" in out
        assert 'xray_scan_up{proxy="direct"} 0' in out
        # DPI block is still appended
        assert 'xray_dpi_telegram_verdict{verdict="ok"} 1' in out

    def test_dpi_only_without_registered_proxy(self):
        """Edge case: DPI ran but no proxy ever registered — render still includes DPI."""
        state = MetricsState()
        state.update_dpi_telegram(
            TelegramReport(
                verdict="ok",
                download=TransferStats(status="ok"),
                upload=TransferStats(status="ok"),
                dc=DcStats(reachable=5, total=5),
            ),
            duration=1.0,
        )
        out = state.render()
        assert "xray_dpi_telegram_up 1" in out
        assert "no proxies registered" not in out
