"""Tests for ICMP ping checker — output parsing and integration."""

import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.icmp_ping_checker import (
    _parse_loss,
    _parse_rtt,
    check_icmp_ping,
)

# -- Unit tests for output parsing --


class TestParseRtt:
    def test_standard_linux_output(self):
        output = "rtt min/avg/max/mdev = 1.234/5.678/9.012/0.345 ms"
        rtt_min, rtt_avg, rtt_max = _parse_rtt(output)
        assert rtt_min == 1.23
        assert rtt_avg == 5.68
        assert rtt_max == 9.01

    def test_high_latency(self):
        output = "rtt min/avg/max/mdev = 120.456/163.789/200.123/30.456 ms"
        rtt_min, rtt_avg, rtt_max = _parse_rtt(output)
        assert rtt_min == 120.46
        assert rtt_avg == 163.79
        assert rtt_max == 200.12

    def test_no_match(self):
        output = "some unrelated output"
        assert _parse_rtt(output) == (None, None, None)

    def test_empty_string(self):
        assert _parse_rtt("") == (None, None, None)


class TestParseLoss:
    def test_no_loss(self):
        output = "3 packets transmitted, 3 received, 0% packet loss, time 2003ms"
        tx, rx, loss = _parse_loss(output)
        assert tx == 3
        assert rx == 3
        assert loss == 0.0

    def test_partial_loss(self):
        output = "3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms"
        tx, rx, loss = _parse_loss(output)
        assert tx == 3
        assert rx == 2
        assert loss == pytest.approx(33.3333)

    def test_total_loss(self):
        output = "3 packets transmitted, 0 received, 100% packet loss, time 2003ms"
        tx, rx, loss = _parse_loss(output)
        assert tx == 3
        assert rx == 0
        assert loss == 100.0

    def test_no_match(self):
        assert _parse_loss("no data") == (None, None, None)


# -- Integration test --


class TestCheckIcmpPing:
    async def test_reachable_host(self):
        result = await check_icmp_ping("127.0.0.1", count=2)
        assert result.check_name == "ICMP Ping"
        assert result.status == CheckStatus.PASS
        assert result.details["latency_avg_ms"] is not None
        assert result.details["packet_loss_pct"] == 0.0

    async def test_unreachable_host(self):
        # 192.0.2.1 is TEST-NET-1 — should be unreachable
        result = await check_icmp_ping("192.0.2.1", count=1)
        assert result.check_name == "ICMP Ping"
        assert result.status == CheckStatus.FAIL
        assert result.details["packet_loss_pct"] == 100.0
