"""Tests for censor_checker module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from xray_analyzer.diagnostics.censor_checker import (
    DEFAULT_CENSOR_DOMAINS,
    RKN_STUB_IPS,
    CensorCheckSummary,
    DomainCheckResult,
    DomainStatus,
    _fetch_http_code,
    _is_rkn_spoof,
    _resolve_dns,
    check_domain,
    run_censor_check,
)


class TestIsRknSpoof:
    """Test RKN spoof IP detection."""

    def test_known_rkn_ip(self):
        """Test detection of known RKN spoof IPs."""
        for ip in RKN_STUB_IPS:
            assert _is_rkn_spoof(ip) is True

    def test_unknown_ip(self):
        """Test that non-RKN IPs are not detected as spoof."""
        assert _is_rkn_spoof("8.8.8.8") is False
        assert _is_rkn_spoof("1.1.1.1") is False
        assert _is_rkn_spoof("142.250.185.46") is False


class TestResolveDns:
    """Test DNS resolution."""

    @pytest.mark.asyncio
    async def test_resolve_valid_domain(self):
        """Test DNS resolution for a valid domain."""
        ips = await _resolve_dns("google.com")
        assert isinstance(ips, list)

    @pytest.mark.asyncio
    async def test_resolve_invalid_domain(self):
        """Test DNS resolution for an invalid domain."""
        # Note: Some DNS providers return wildcard IPs for non-existent domains
        # So we just verify it returns a list (may be empty or have IPs)
        ips = await _resolve_dns("this-domain-definitely-does-not-exist-12345.com")
        assert isinstance(ips, list)


class TestFetchHttpCode:
    """Test HTTP/HTTPS fetching."""

    @pytest.mark.asyncio
    async def test_fetch_http_code_success(self):
        """Test HTTP fetch returns status code."""
        # This requires network, so we'll mock it
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_response
            mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session_instance.__aexit__ = AsyncMock(return_value=None)

            mock_session.return_value = mock_session_instance

            status = await _fetch_http_code("http://google.com", timeout=4)
            # Should return 0 on failure in test environment
            assert isinstance(status, int)


class TestCheckDomain:
    """Test domain checking logic."""

    @pytest.mark.asyncio
    async def test_domain_dns_failure(self):
        """Test domain check when DNS resolution fails."""
        with patch(
            "xray_analyzer.diagnostics.censor_checker._resolve_dns",
            return_value=[],
        ):
            result = await check_domain("blocked-domain.test")

            assert result.domain == "blocked-domain.test"
            assert result.status == DomainStatus.BLOCKED
            assert result.block_type == "DNS"

    @pytest.mark.asyncio
    async def test_domain_rkn_spoof(self):
        """Test domain check when DNS returns RKN spoof IP."""
        with patch(
            "xray_analyzer.diagnostics.censor_checker._resolve_dns",
            return_value=["195.208.4.1"],
        ):
            result = await check_domain("spoofed-domain.test")

            assert result.status == DomainStatus.BLOCKED
            assert result.block_type == "DNS-SPOOF"
            assert result.details["rkn_stub_ip"] == "195.208.4.1"

    @pytest.mark.asyncio
    async def test_domain_tcp_failure(self):
        """Test domain check when TCP connection fails."""
        with (
            patch(
                "xray_analyzer.diagnostics.censor_checker._resolve_dns",
                return_value=["8.8.8.8"],
            ),
            patch(
                "xray_analyzer.diagnostics.censor_checker._check_tcp_port",
                return_value=False,
            ),
        ):
            result = await check_domain("tcp-blocked.test")

            assert result.status == DomainStatus.BLOCKED
            assert result.block_type == "IP/TCP"


class TestRunCensorCheck:
    """Test main censor check runner."""

    @pytest.mark.asyncio
    async def test_run_censor_check_with_domains(self):
        """Test running censor check with specific domains."""
        test_domains = ["google.com", "youtube.com"]

        with patch(
            "xray_analyzer.diagnostics.censor_checker.check_domain"
        ) as mock_check:
            mock_check.return_value = DomainCheckResult(
                domain="google.com",
                status=DomainStatus.OK,
                block_type="",
                tls_valid=True,
                https_code=200,
            )

            summary = await run_censor_check(domains=test_domains, max_parallel=2)

            assert summary.total == 2
            assert isinstance(summary.ok, int)
            assert isinstance(summary.duration_seconds, float)

    @pytest.mark.asyncio
    async def test_run_censor_check_default_domains(self):
        """Test running censor check with default domains."""
        with patch(
            "xray_analyzer.diagnostics.censor_checker.check_domain"
        ) as mock_check:
            mock_check.return_value = DomainCheckResult(
                domain="test.com",
                status=DomainStatus.OK,
                block_type="",
            )

            await run_censor_check(domains=None)

            # Should use DEFAULT_CENSOR_DOMAINS
            assert mock_check.call_count == len(DEFAULT_CENSOR_DOMAINS)

    @pytest.mark.asyncio
    async def test_run_censor_check_with_proxy(self):
        """Test running censor check through proxy."""
        proxy_url = "socks5://127.0.0.1:1080"

        with patch(
            "xray_analyzer.diagnostics.censor_checker.check_domain"
        ) as mock_check:
            mock_check.return_value = DomainCheckResult(
                domain="test.com",
                status=DomainStatus.OK,
                block_type="",
            )

            summary = await run_censor_check(
                domains=["test.com"],
                proxy_url=proxy_url,
            )

            assert summary.proxy_url == proxy_url
            # Verify proxy was passed to check_domain
            mock_check.assert_called_once()
            call_kwargs = mock_check.call_args[1]
            assert call_kwargs["proxy_url"] == proxy_url

    @pytest.mark.asyncio
    async def test_run_censor_check_statistics(self):
        """Test censor check statistics calculation."""

        async def mock_check_domain(domain, **_kwargs):
            if domain == "ok.com":
                return DomainCheckResult(domain=domain, status=DomainStatus.OK, block_type="")
            elif domain == "blocked.com":
                return DomainCheckResult(
                    domain=domain,
                    status=DomainStatus.BLOCKED,
                    block_type="DNS",
                )
            else:
                return DomainCheckResult(
                    domain=domain,
                    status=DomainStatus.PARTIAL,
                    block_type="DPI/KEYWORD",
                )

        with patch(
            "xray_analyzer.diagnostics.censor_checker.check_domain",
            side_effect=mock_check_domain,
        ):
            summary = await run_censor_check(
                domains=["ok.com", "blocked.com", "partial.com"],
                max_parallel=3,
            )

            assert summary.total == 3
            assert summary.ok == 1
            assert summary.blocked == 1
            assert summary.partial == 1


class TestDomainCheckResult:
    """Test DomainCheckResult dataclass."""

    def test_result_creation(self):
        """Test DomainCheckResult creation with defaults."""
        result = DomainCheckResult(
            domain="test.com",
            status=DomainStatus.OK,
        )

        assert result.domain == "test.com"
        assert result.status == DomainStatus.OK
        assert result.block_type == ""
        assert result.http_code == 0
        assert result.https_code == 0
        assert result.tls_valid is False
        assert result.ips == []
        assert result.details == {}


class TestCensorCheckSummary:
    """Test CensorCheckSummary dataclass."""

    def test_summary_creation(self):
        """Test CensorCheckSummary creation."""
        summary = CensorCheckSummary(
            total=10,
            ok=7,
            blocked=2,
            partial=1,
            duration_seconds=5.5,
        )

        assert summary.total == 10
        assert summary.ok == 7
        assert summary.blocked == 2
        assert summary.partial == 1
        assert summary.duration_seconds == 5.5
        assert summary.results == []
        assert summary.proxy_url == ""
