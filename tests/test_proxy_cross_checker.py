"""Tests for proxy cross checker."""

import pytest
from aiohttp import ServerDisconnectedError
from aioresponses import aioresponses

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.proxy_cross_checker import check_via_proxy


@pytest.mark.asyncio
async def test_cross_proxy_success():
    """Cross-proxy test should pass when target responds with any HTTP status."""
    with aioresponses() as mocked:
        mocked.get(
            "http://target.example.com:443/",
            status=200,
        )

        result = await check_via_proxy(
            "target.example.com",
            443,
            "http://working-proxy:8080",
            proxy_name="Working Proxy",
        )

        assert result.status == CheckStatus.PASS
        assert result.check_name == "Cross-Proxy Connectivity"
        assert "Working Proxy" in result.message
        assert result.details["target_host"] == "target.example.com"
        assert result.details["target_port"] == 443


@pytest.mark.asyncio
async def test_cross_proxy_non_http_server_pass():
    """Cross-proxy test should pass when server disconnects (non-HTTP proxy server)."""
    with aioresponses() as mocked:
        mocked.get(
            "http://target.example.com:443/",
            exception=ServerDisconnectedError(),
        )

        result = await check_via_proxy(
            "target.example.com",
            443,
            "http://working-proxy:8080",
            proxy_name="Working Proxy",
        )

        assert result.status == CheckStatus.PASS
        assert result.details["target_host"] == "target.example.com"
        assert result.details["target_port"] == 443


@pytest.mark.asyncio
async def test_cross_proxy_details():
    """Cross-proxy test should include proper details."""
    with aioresponses() as mocked:
        mocked.get(
            "http://test.example.com:8080/",
            status=200,
            body="OK",
        )

        result = await check_via_proxy(
            "test.example.com",
            8080,
            "socks5://proxy:1080",
            proxy_name="Test Proxy",
        )

        assert result.details["target_host"] == "test.example.com"
        assert result.details["target_port"] == 8080
        assert result.details["proxy_name"] == "Test Proxy"
        assert "duration_ms" in result.details
