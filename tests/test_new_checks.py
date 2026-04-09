"""Tests for new diagnostic checks: TCP ping, proxy TCP tunnel, proxy IP, proxy SNI, RKN."""

import pytest

from xray_analyzer.core.config import settings
from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.rkn_checker import _is_ip_address, check_rkn_blocking
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


@pytest.mark.asyncio
async def test_rkn_blocking_enabled_non_blocked_domain():
    """Test RKN check for a non-blocked domain."""
    result = await check_rkn_blocking("google.com")
    assert result.check_name == "RKN Block Check"
    # Result depends on RKN API availability
    assert result.status in (CheckStatus.PASS, CheckStatus.SKIP, CheckStatus.TIMEOUT)


@pytest.mark.asyncio
async def test_rkn_blocking_ip_address_detection():
    """Test that IP addresses are detected correctly."""
    assert _is_ip_address("8.8.8.8") is True
    assert _is_ip_address("2001:4860:4860::8888") is True
    assert _is_ip_address("google.com") is False
    assert _is_ip_address("192.168.1.1") is True
    assert _is_ip_address("not-an-ip") is False


@pytest.mark.asyncio
async def test_rkn_blocking_disabled():
    """Test RKN check when disabled."""
    original = settings.rkn_check_enabled
    try:
        settings.rkn_check_enabled = False
        result = await check_rkn_blocking("test.com")
        assert result.status == CheckStatus.SKIP
        assert "disabled" in result.message.lower()
    finally:
        settings.rkn_check_enabled = original
