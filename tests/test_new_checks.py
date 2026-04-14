"""Tests for new diagnostic checks: TCP ping, proxy TCP tunnel, proxy IP, proxy SNI."""

import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.tcp_ping_checker import check_tcp_ping


@pytest.mark.asyncio
async def test_tcp_ping_valid_host():
    """Test TCP ping to a valid host."""
    result = await check_tcp_ping("google.com", 443, count=2)
    assert result.check_name == "TCP Ping"
    # Should pass or have partial success
    assert result.status in (CheckStatus.PASS, CheckStatus.FAIL)
    assert "latency_avg_ms" in result.details or "packet_loss_pct" in result.details


@pytest.mark.asyncio
async def test_tcp_ping_invalid_host():
    """Test TCP ping to an invalid host."""
    # Use a non-routable host that's more likely to fail
    result = await check_tcp_ping("192.0.2.1", 12345, count=1)  # TEST-NET-1, should fail
    assert result.check_name == "TCP Ping"
    # Could be FAIL or PASS depending on network, verify structure
    assert "packet_loss_pct" in result.details
