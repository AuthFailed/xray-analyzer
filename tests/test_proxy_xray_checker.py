"""Tests for proxy Xray checker with IP fallback."""

from unittest.mock import patch

import pytest

from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.diagnostics.proxy_xray_checker import check_proxy_via_xray
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL


def _make_share() -> ProxyShareURL:
    """Create a minimal VLESS share URL for testing."""
    return ProxyShareURL(
        protocol="vless",
        name="Test Proxy",
        server="example.com",
        port=443,
        raw_url="vless://test-uuid@example.com:443?security=reality#Test+Proxy",
        uuid="test-uuid",
        security="reality",
        sni="example.com",
        fp="chrome",
        pbk="test-pbk",
        sid="test-sid",
    )


@pytest.mark.asyncio
async def test_xray_test_passes_no_fallback():
    """When main test passes, no fallback IP test should be performed."""
    share = _make_share()

    with patch("xray_analyzer.diagnostics.proxy_xray_checker._run_xray_tests") as mock_run:
        # Simulate successful connectivity (with домен suffix)
        mock_run.return_value = [
            DiagnosticResult(
                check_name="Proxy Xray Connectivity (домен: example.com)",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message="Test Proxy (vless): подключился",
                details={"protocol": "vless", "server": "example.com"},
            )
        ]

        results = await check_proxy_via_xray(share, fallback_server_ip="1.2.3.4")

        # Should only have the main test results
        assert len(results) == 1
        assert results[0].status == CheckStatus.PASS
        # _run_xray_tests should be called only once (no fallback)
        assert mock_run.call_count == 1


@pytest.mark.asyncio
async def test_xray_test_fallback_on_timeout():
    """When main test times out, fallback IP test should be performed."""
    share = _make_share()

    with patch("xray_analyzer.diagnostics.proxy_xray_checker._run_xray_tests") as mock_run:

        def side_effect(share_obj, label_suffix=""):
            if "IP:" in label_suffix:
                # Fallback test — should pass
                return [
                    DiagnosticResult(
                        check_name=f"Proxy Xray Connectivity{label_suffix}",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message="Test Proxy (vless): подключился через IP",
                        details={"protocol": "vless", "server": share_obj.server},
                    )
                ]
            else:
                # Main test (домен suffix) — fails
                return [
                    DiagnosticResult(
                        check_name=f"Proxy Xray Connectivity{label_suffix}",
                        status=CheckStatus.TIMEOUT,
                        severity=CheckSeverity.CRITICAL,
                        message="Test Proxy (vless): таймаут подключения",
                        details={"protocol": "vless", "server": "example.com"},
                    )
                ]

        mock_run.side_effect = side_effect

        results = await check_proxy_via_xray(share, fallback_server_ip="1.2.3.4")

        # When fallback IP succeeds, failed domain results are replaced with PASS
        assert len(results) == 2
        assert results[0].status == CheckStatus.PASS
        assert results[0].severity == CheckSeverity.WARNING
        assert results[1].status == CheckStatus.PASS
        assert mock_run.call_count == 2


@pytest.mark.asyncio
async def test_xray_test_fallback_on_fail():
    """When main test fails (not timeout), fallback IP test should be performed."""
    share = _make_share()

    with patch("xray_analyzer.diagnostics.proxy_xray_checker._run_xray_tests") as mock_run:

        def side_effect(share_obj, label_suffix=""):
            if "IP:" in label_suffix:
                return [
                    DiagnosticResult(
                        check_name=f"Proxy Xray Connectivity{label_suffix}",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message="Test Proxy (vless): подключился через IP",
                        details={"protocol": "vless", "server": share_obj.server},
                    )
                ]
            else:
                return [
                    DiagnosticResult(
                        check_name=f"Proxy Xray Connectivity{label_suffix}",
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.CRITICAL,
                        message="Test Proxy (vless): ошибка подключения",
                        details={"protocol": "vless", "server": "example.com"},
                    )
                ]

        mock_run.side_effect = side_effect

        results = await check_proxy_via_xray(share, fallback_server_ip="1.2.3.4")

        # When fallback IP succeeds, failed domain results are replaced with PASS
        assert len(results) == 2
        assert results[0].status == CheckStatus.PASS
        assert results[0].severity == CheckSeverity.WARNING
        assert results[1].status == CheckStatus.PASS
        assert mock_run.call_count == 2


@pytest.mark.asyncio
async def test_no_fallback_when_ip_not_provided():
    """When no fallback IP is provided, no fallback test should be performed."""
    share = _make_share()

    with patch("xray_analyzer.diagnostics.proxy_xray_checker._run_xray_tests") as mock_run:
        mock_run.return_value = [
            DiagnosticResult(
                check_name="Proxy Xray Connectivity (домен: example.com)",
                status=CheckStatus.TIMEOUT,
                severity=CheckSeverity.CRITICAL,
                message="Test Proxy (vless): таймаут подключения",
                details={"protocol": "vless", "server": "example.com"},
            )
        ]

        results = await check_proxy_via_xray(share, fallback_server_ip=None)

        # Should only have main test results, no fallback
        assert len(results) == 1
        assert mock_run.call_count == 1
