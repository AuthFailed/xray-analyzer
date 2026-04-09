"""Tests for RKN throttle checker."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from xray_analyzer.core.models import CheckSeverity, CheckStatus
from xray_analyzer.diagnostics.proxy_rkn_throttle_checker import (
    RKN_THROTTLE_MAX_BYTES,
    RKN_THROTTLE_MIN_BYTES,
    check_rkn_throttle_direct,
    check_rkn_throttle_via_proxy,
)


class MockResponseContent:
    """Mock async response content with chunked iteration."""

    def __init__(self, chunks: list[bytes], simulate_disconnect_after: int | None = None):
        self.chunks = chunks
        self.simulate_disconnect_after = simulate_disconnect_after
        self._iterated = 0

    async def iter_chunked(self, _chunk_size: int):
        """Simulate chunked iteration with optional disconnect."""
        for chunk in self.chunks:
            self._iterated += 1
            if self.simulate_disconnect_after and self._iterated > self.simulate_disconnect_after:
                raise aiohttp.ServerDisconnectedError("Simulated disconnect")
            yield chunk


class MockResponse:
    """Mock aiohttp response."""

    def __init__(
        self,
        status: int = 200,
        chunks: list[bytes] | None = None,
        simulate_disconnect_after: int | None = None,
    ):
        self.status = status
        if chunks is None:
            # Default: create chunks that simulate 16KB throttle
            chunks = [b"x" * 4096 for _ in range(4)]  # 16KB total
        self.content = MockResponseContent(chunks, simulate_disconnect_after)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class MockSessionContext:
    """Mock aiohttp ClientSession context manager."""

    def __init__(self, response: MockResponse):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def get(self, _url, **_kwargs):
        """Return the mock response."""
        return self.response


@pytest.mark.asyncio
async def test_rkn_throttle_detected_when_16kb_cutoff():
    """Test that RKN throttle is detected when connection cuts after ~16KB."""
    # Simulate 4 chunks of 4KB = 16KB, then disconnect
    chunks = [b"x" * 4096 for _ in range(4)]  # 16KB total
    mock_response = MockResponse(status=200, chunks=chunks, simulate_disconnect_after=4)
    mock_session = MockSessionContext(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await check_rkn_throttle_direct("example.com", 443)

    assert result.status == CheckStatus.FAIL
    assert result.severity == CheckSeverity.CRITICAL
    assert "RKN" in result.message or "DPI" in result.message or "throttle" in result.message.lower()
    assert result.details["total_bytes_received"] == 16384  # 4 * 4096


@pytest.mark.asyncio
async def test_rkn_throttle_passes_when_full_data_received():
    """Test that check passes when more than throttle threshold is received."""
    # Simulate 20 chunks of 4KB = 80KB (well above throttle threshold)
    chunks = [b"x" * 4096 for _ in range(20)]  # 80KB total
    mock_response = MockResponse(status=200, chunks=chunks)
    mock_session = MockSessionContext(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await check_rkn_throttle_direct("example.com", 443)

    assert result.status == CheckStatus.PASS
    assert result.details["total_bytes_received"] > RKN_THROTTLE_MAX_BYTES


@pytest.mark.asyncio
async def test_rkn_throttle_passes_with_small_response():
    """Test that check passes with small responses (not throttled)."""
    # Small response (1KB) — not a throttle pattern
    chunks = [b"x" * 1024]
    mock_response = MockResponse(status=200, chunks=chunks)
    mock_session = MockSessionContext(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await check_rkn_throttle_direct("example.com", 443)

    assert result.status == CheckStatus.PASS
    assert result.details["total_bytes_received"] == 1024


@pytest.mark.asyncio
async def test_rkn_throttle_timeout_detected():
    """Test that timeout is handled correctly."""
    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=TimeoutError())
        mock_session_cls.return_value = MagicMock(
            __aenter__=AsyncMock(return_value=mock_session),
            __aexit__=AsyncMock(return_value=None),
        )

        result = await check_rkn_throttle_direct("example.com", 443)

    assert result.status in (CheckStatus.TIMEOUT, CheckStatus.FAIL)


@pytest.mark.asyncio
async def test_rkn_throttle_via_proxy_detected():
    """Test that RKN throttle is detected when checking via proxy."""
    chunks = [b"x" * 4096 for _ in range(4)]  # 16KB total
    mock_response = MockResponse(status=200, chunks=chunks, simulate_disconnect_after=4)
    mock_session = MockSessionContext(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await check_rkn_throttle_via_proxy(
            "http://proxy.example.com:8080",
            "blocked-domain.com",
        )

    assert result.status == CheckStatus.FAIL
    assert result.severity == CheckSeverity.CRITICAL
    assert "proxy" in result.details.get("proxy", "").lower() or "через прокси" in result.check_name.lower()


@pytest.mark.asyncio
async def test_rkn_throttle_recommendations_present():
    """Test that recommendations are provided when throttle is detected."""
    chunks = [b"x" * 4096 for _ in range(5)]  # 20KB (at boundary)
    mock_response = MockResponse(status=200, chunks=chunks, simulate_disconnect_after=5)
    mock_session = MockSessionContext(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await check_rkn_throttle_direct("example.com", 443)

    # Recommendations are in the message text
    assert "DPI" in result.message or "throttle" in result.message.lower() or "RKN" in result.message


@pytest.mark.asyncio
async def test_rkn_throttle_details_populated():
    """Test that diagnostic details are properly populated."""
    chunks = [b"x" * 4096 for _ in range(10)]  # 40KB (should pass)
    mock_response = MockResponse(status=200, chunks=chunks)
    mock_session = MockSessionContext(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await check_rkn_throttle_direct("example.com", 443)

    assert "target" in result.details
    assert "url" in result.details
    assert "total_bytes_received" in result.details
    assert "http_status" in result.details
    assert "duration_ms" in result.details
    assert result.details["target"] == "example.com"


@pytest.mark.asyncio
async def test_rkn_throttle_boundary_14kb():
    """Test throttle detection at lower boundary (~14KB)."""
    # 14KB = 3.5 chunks, simulate disconnect after 3 chunks (12KB) + partial
    chunks = [b"x" * 4096 for _ in range(3)] + [b"x" * 2048]  # 14KB total
    mock_response = MockResponse(status=206, chunks=chunks, simulate_disconnect_after=4)
    mock_session = MockSessionContext(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await check_rkn_throttle_direct("example.com", 443)

    # 14KB is at the boundary — should be detected as throttled
    total = result.details["total_bytes_received"]
    assert RKN_THROTTLE_MIN_BYTES - 1024 <= total <= RKN_THROTTLE_MAX_BYTES + 1024
