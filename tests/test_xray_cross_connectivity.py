"""Tests for Xray cross-proxy connectivity."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.proxy_cross_checker import check_xray_cross_connectivity

SOCKS_URL = "socks5://user:pass@127.0.0.1:19001"


@pytest.mark.asyncio
async def test_xray_cross_connectivity_success():
    """Test successful cross-connectivity through a pre-started Xray tunnel."""
    with patch("xray_analyzer.diagnostics.proxy_cross_checker.aiohttp.ClientSession") as mock_session_cls:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.close = AsyncMock()
        mock_session_cls.return_value = mock_session

        result = await check_xray_cross_connectivity(
            target_host="problematic.example.com",
            target_port=443,
            target_protocol="vless",
            socks_url=SOCKS_URL,
            working_proxy_name="Working Proxy",
            working_proxy_protocol="vless",
        )

        assert result.status == CheckStatus.PASS
        assert "доступен через" in result.message
        assert result.details["target_host"] == "problematic.example.com"
        assert result.details["target_port"] == 443
        assert result.details["working_proxy"] == "Working Proxy"
        assert len(result.recommendations) > 0


@pytest.mark.asyncio
async def test_xray_cross_connectivity_timeout():
    """Test cross-connectivity timeout through a pre-started Xray tunnel."""
    with patch("xray_analyzer.diagnostics.proxy_cross_checker.aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=TimeoutError())
        mock_session.close = AsyncMock()
        mock_session_cls.return_value = mock_session

        result = await check_xray_cross_connectivity(
            target_host="problematic.example.com",
            target_port=443,
            target_protocol="trojan",
            socks_url=SOCKS_URL,
            working_proxy_name="Working Proxy",
            working_proxy_protocol="vless",
        )

        assert result.status == CheckStatus.TIMEOUT
        assert "Таймаут через" in result.message
        assert len(result.recommendations) > 0


@pytest.mark.asyncio
async def test_xray_cross_connectivity_http_error():
    """Test cross-connectivity when HTTP error occurs."""
    with patch("xray_analyzer.diagnostics.proxy_cross_checker.aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=aiohttp.ClientError("Connection refused"))
        mock_session.close = AsyncMock()
        mock_session_cls.return_value = mock_session

        result = await check_xray_cross_connectivity(
            target_host="problematic.example.com",
            target_port=443,
            target_protocol="vless",
            socks_url=SOCKS_URL,
            working_proxy_name="Working Proxy",
            working_proxy_protocol="vless",
        )

        assert result.status == CheckStatus.FAIL
        assert "Ошибка через" in result.message
