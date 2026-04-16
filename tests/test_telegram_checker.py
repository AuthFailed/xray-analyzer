"""Tests for diagnostics.telegram_checker."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.telegram_checker import (
    DcStats,
    TelegramReport,
    TransferStats,
    _classify_transfer,
    _overall_verdict,
    _run_download,
    _run_upload,
    _tcp_ping,
    to_diagnostic,
)


class TestClassifyTransfer:
    def test_zero_bytes_is_blocked(self):
        assert _classify_transfer(0, 10_000, 30.0, 0, 10.0) == "blocked"

    def test_full_size_is_ok(self):
        assert _classify_transfer(10_000, 10_000, 30.0, 10, 10.0) == "ok"

    def test_near_full_is_ok(self):
        assert _classify_transfer(9900, 10_000, 30.0, 10, 10.0) == "ok"

    def test_old_last_data_is_stalled(self):
        # Got some data, but nothing for 15s > 10s stall_timeout → stalled
        assert _classify_transfer(5000, 10_000, 30.0, 15, 10.0) == "stalled"

    def test_recent_data_but_overall_timeout_is_slow(self):
        # Last data 5s before "now" (30 - 25 = 5s < stall_timeout) → slow
        assert _classify_transfer(5000, 10_000, 30.0, 25, 10.0) == "slow"


class TestOverallVerdict:
    def test_all_ok(self):
        dl = TransferStats(status="ok", bytes_total=10, duration_s=1, peak_bps=1, avg_bps=1)
        ul = TransferStats(status="ok", bytes_total=10, duration_s=1, peak_bps=1, avg_bps=1)
        dc = DcStats(reachable=5, total=5)
        assert _overall_verdict(dl, ul, dc) == "ok"

    def test_blocked_when_both_dead_and_no_dcs(self):
        dl = TransferStats(status="blocked")
        ul = TransferStats(status="blocked")
        dc = DcStats(reachable=0, total=5)
        assert _overall_verdict(dl, ul, dc) == "blocked"

    def test_slow_when_stalled(self):
        dl = TransferStats(status="stalled", bytes_total=1000, duration_s=30)
        ul = TransferStats(status="ok", bytes_total=1000, duration_s=3, peak_bps=1, avg_bps=1)
        dc = DcStats(reachable=5, total=5)
        assert _overall_verdict(dl, ul, dc) == "slow"

    def test_partial_when_some_dcs_down(self):
        dl = TransferStats(status="ok", bytes_total=1, peak_bps=1, avg_bps=1)
        ul = TransferStats(status="ok", bytes_total=1, peak_bps=1, avg_bps=1)
        dc = DcStats(reachable=3, total=5)
        assert _overall_verdict(dl, ul, dc) == "partial"

    def test_error_fallback(self):
        dl = TransferStats(status="error")
        ul = TransferStats(status="ok", bytes_total=1, peak_bps=1, avg_bps=1)
        dc = DcStats(reachable=5, total=5)
        assert _overall_verdict(dl, ul, dc) == "error"


@pytest.mark.asyncio
class TestRunnersSwallowCancellation:
    """Regression for the real-network run of `dpi telegram` where POST against
    a closed 149.154.167.99 fails immediately, triggering asyncio task cleanup.
    Cancelling a task mid-`asyncio.sleep` raises `CancelledError` (a BaseException
    in 3.11+), which must not escape the runner."""

    async def test_upload_runner_cleans_up_on_post_failure(self):
        # With an unreachable upload IP and a tight total timeout, _post raises
        # quickly; the watchdog task sits inside asyncio.sleep and gets cancelled.
        stats = await _run_upload(stall_timeout=1.0, total_timeout=2.0, proxy=None)
        # We don't care about the classification outcome here — just that the
        # coroutine returns cleanly instead of raising CancelledError.
        assert stats.status in {"blocked", "slow", "stalled", "ok"}

    async def test_download_runner_cleans_up_on_fetch_failure(self):
        # Point at a host that does not exist → _reader raises; watchdog cancels.
        with patch(
            "xray_analyzer.diagnostics.telegram_checker.MEDIA_URL",
            "https://127.0.0.1:1/no-such-file",
        ):
            stats = await _run_download(stall_timeout=1.0, total_timeout=2.0, proxy=None)
        assert stats.status in {"blocked", "slow", "stalled", "ok"}


@pytest.mark.asyncio
class TestTcpPing:
    async def test_real_local_server_reachable(self):
        async def handle(_r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            w.close()

        server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]
        try:
            ok, rtt = await _tcp_ping("127.0.0.1", port, timeout=2.0)
        finally:
            server.close()
            await server.wait_closed()
        assert ok is True
        assert rtt is not None and rtt >= 0

    async def test_unreachable_port_returns_false(self):
        # Port 1 on localhost is unlikely to answer
        ok, rtt = await _tcp_ping("127.0.0.1", 1, timeout=0.5)
        assert ok is False
        assert rtt is None


class TestToDiagnostic:
    def test_ok_report_is_pass(self):
        report = TelegramReport(
            verdict="ok",
            download=TransferStats(status="ok", bytes_total=1, duration_s=1, peak_bps=1, avg_bps=1),
            upload=TransferStats(status="ok", bytes_total=1, duration_s=1, peak_bps=1, avg_bps=1),
            dc=DcStats(reachable=5, total=5),
        )
        d = to_diagnostic(report)
        assert d.status == CheckStatus.PASS
        assert "ok" in d.message

    def test_blocked_report_is_fail(self):
        report = TelegramReport(
            verdict="blocked",
            download=TransferStats(status="blocked"),
            upload=TransferStats(status="blocked"),
            dc=DcStats(reachable=0, total=5),
        )
        d = to_diagnostic(report)
        assert d.status == CheckStatus.FAIL
        assert "blocked" in d.message

    def test_slow_report_is_warn(self):
        report = TelegramReport(
            verdict="slow",
            download=TransferStats(status="stalled", bytes_total=1000, duration_s=30, drop_at_sec=10),
            upload=TransferStats(status="ok", bytes_total=1, duration_s=1, peak_bps=1, avg_bps=1),
            dc=DcStats(reachable=5, total=5),
        )
        d = to_diagnostic(report)
        assert d.status == CheckStatus.WARN
        assert d.details["download"]["drop_at_sec"] == 10
