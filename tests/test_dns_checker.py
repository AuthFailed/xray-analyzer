"""Tests for DNS checker."""

import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.dns_checker import check_dns_resolution


@pytest.mark.asyncio
async def test_dns_resolution_valid_host():
    """Test DNS resolution for a known valid host."""
    result = await check_dns_resolution("google.com")
    assert result.status == CheckStatus.PASS
    assert result.check_name == "DNS Resolution"
    assert len(result.details["resolved_ips"]) > 0


@pytest.mark.asyncio
async def test_dns_resolution_invalid_host():
    """Test DNS resolution for an invalid host."""
    result = await check_dns_resolution("this-host-definitely-does-not-exist-12345.invalid")
    assert result.status == CheckStatus.FAIL
    assert result.check_name == "DNS Resolution"
