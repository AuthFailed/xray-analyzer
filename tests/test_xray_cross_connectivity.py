"""Tests for Xray cross-proxy connectivity."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.proxy_cross_checker import check_xray_cross_connectivity
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL


@pytest.fixture
def working_share():
    """Create a mock working proxy share URL."""
    return ProxyShareURL(
        protocol="vless",
        server="working.example.com",
        port=443,
        uuid="test-uuid-1234",
        flow="",
        network="tcp",
        security="reality",
        pbk="test-pubkey",
        sid="",
        spx="",
        sni="working.example.com",
        fp="chrome",
        host="working.example.com",
        path="/",
        service_name="",
        name="Working Proxy",
        raw_url="vless://test-uuid-1234@working.example.com:443",
    )


@pytest.mark.asyncio
async def test_xray_cross_connectivity_success(working_share):
    """Test successful cross-connectivity through working Xray proxy."""
    with (
        patch("xray_analyzer.diagnostics.proxy_cross_checker.XrayInstance") as mock_xray_cls,
        patch("xray_analyzer.diagnostics.proxy_cross_checker.aiohttp.ClientSession") as mock_session_cls,
    ):
        # Mock XrayInstance
        mock_xray = AsyncMock()
        mock_xray.start = AsyncMock(return_value=19001)
        mock_xray.stop = AsyncMock()
        mock_xray_cls.return_value = mock_xray

        # Mock aiohttp session
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session_cls.return_value = mock_session

        result = await check_xray_cross_connectivity(
            target_host="problematic.example.com",
            target_port=443,
            target_protocol="vless",
            working_proxy_share=working_share,
            working_proxy_name="Working Proxy",
        )

        assert result.status == CheckStatus.PASS
        assert "доступен через" in result.message
        assert result.details["target_host"] == "problematic.example.com"
        assert result.details["target_port"] == 443
        assert result.details["working_proxy"] == "Working Proxy"
        assert len(result.details.get("recommendations", [])) > 0


@pytest.mark.asyncio
async def test_xray_cross_connectivity_timeout(working_share):
    """Test cross-connectivity timeout through working Xray proxy."""
    with (
        patch("xray_analyzer.diagnostics.proxy_cross_checker.XrayInstance") as mock_xray_cls,
        patch("xray_analyzer.diagnostics.proxy_cross_checker.aiohttp.ClientSession") as mock_session_cls,
    ):
        # Mock XrayInstance
        mock_xray = AsyncMock()
        mock_xray.start = AsyncMock(return_value=19001)
        mock_xray.stop = AsyncMock()
        mock_xray_cls.return_value = mock_xray

        # Mock aiohttp session to raise TimeoutError
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=TimeoutError())
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session_cls.return_value = mock_session

        result = await check_xray_cross_connectivity(
            target_host="problematic.example.com",
            target_port=443,
            target_protocol="trojan",
            working_proxy_share=working_share,
            working_proxy_name="Working Proxy",
        )

        assert result.status == CheckStatus.TIMEOUT
        assert "Таймаут через" in result.message
        assert len(result.details.get("recommendations", [])) > 0


@pytest.mark.asyncio
async def test_xray_cross_connectivity_xray_start_failure(working_share):
    """Test cross-connectivity when Xray fails to start."""
    with patch("xray_analyzer.diagnostics.proxy_cross_checker.XrayInstance") as mock_xray_cls:
        # Mock XrayInstance to fail on start
        mock_xray = AsyncMock()
        mock_xray.start = AsyncMock(side_effect=RuntimeError("Xray binary not found"))
        mock_xray_cls.return_value = mock_xray

        result = await check_xray_cross_connectivity(
            target_host="problematic.example.com",
            target_port=443,
            target_protocol="vless",
            working_proxy_share=working_share,
            working_proxy_name="Working Proxy",
        )

        assert result.status == CheckStatus.SKIP
        assert "Не удалось запустить" in result.message


@pytest.mark.asyncio
async def test_xray_cross_connectivity_http_error(working_share):
    """Test cross-connectivity when HTTP error occurs."""
    with (
        patch("xray_analyzer.diagnostics.proxy_cross_checker.XrayInstance") as mock_xray_cls,
        patch("xray_analyzer.diagnostics.proxy_cross_checker.aiohttp.ClientSession") as mock_session_cls,
    ):
        # Mock XrayInstance
        mock_xray = AsyncMock()
        mock_xray.start = AsyncMock(return_value=19001)
        mock_xray.stop = AsyncMock()
        mock_xray_cls.return_value = mock_xray

        # Mock aiohttp session to raise ClientError
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=aiohttp.ClientError("Connection refused"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session_cls.return_value = mock_session

        result = await check_xray_cross_connectivity(
            target_host="problematic.example.com",
            target_port=443,
            target_protocol="vless",
            working_proxy_share=working_share,
            working_proxy_name="Working Proxy",
        )

        assert result.status == CheckStatus.FAIL
        assert "Ошибка через" in result.message
