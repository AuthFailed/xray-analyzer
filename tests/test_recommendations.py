"""Tests for smart recommendations based on cross-proxy test results."""

from xray_analyzer.core.analyzer import XrayAnalyzer
from xray_analyzer.core.models import (
    CheckSeverity,
    CheckStatus,
    DiagnosticResult,
    HostDiagnostic,
)


def _make_xray_result(
    status: CheckStatus,
    label: str = "домен: test.example.com",
    server: str = "test.example.com",
    protocol: str = "vless",
) -> DiagnosticResult:
    """Helper to create Xray connectivity result."""
    msg = "OK" if status == CheckStatus.PASS else "таймаут подключения"
    return DiagnosticResult(
        check_name=f"Proxy Xray Connectivity ({label})",
        status=status,
        severity=CheckSeverity.CRITICAL if status != CheckStatus.PASS else CheckSeverity.INFO,
        message=msg,
        details={
            "protocol": protocol,
            "server": server,
            "port": 443,
            "http_status": 204 if status == CheckStatus.PASS else None,
        },
    )


def _make_cross_result(
    status: CheckStatus,
    working_proxy: str = "🇺🇸 США",
) -> DiagnosticResult:
    """Helper to create cross-proxy connectivity result."""
    return DiagnosticResult(
        check_name="Xray Cross-Proxy Connectivity",
        status=status,
        severity=CheckSeverity.CRITICAL if status != CheckStatus.PASS else CheckSeverity.INFO,
        message="OK" if status == CheckStatus.PASS else "timeout",
        details={
            "target_host": "test.example.com",
            "target_port": 443,
            "working_proxy": working_proxy,
            "http_status": 204 if status == CheckStatus.PASS else None,
        },
    )


def _make_dns_result(status: CheckStatus) -> DiagnosticResult:
    """Helper to create DNS resolution result."""
    return DiagnosticResult(
        check_name="DNS Resolution (Check-Host)",
        status=status,
        severity=CheckSeverity.CRITICAL if status != CheckStatus.PASS else CheckSeverity.INFO,
        message="OK" if status == CheckStatus.PASS else "DNS mismatch",
        details={
            "local_ips": ["1.2.3.4"] if status == CheckStatus.PASS else ["198.18.0.1"],
            "checkhost_ips": ["1.2.3.4"] if status == CheckStatus.PASS else ["5.6.7.8"],
        },
    )


def _make_throttle_result(status: CheckStatus, bytes_received: int = 0) -> DiagnosticResult:
    """Helper to create RKN throttle result.

    bytes_received=0 → IP fully blocked (timeout)
    bytes_received=16000 → DPI throttle (16KB cutoff)
    """
    if bytes_received == 0:
        msg = "IP полностью заблокирован: не удалось установить соединение за 8s"
    else:
        msg = f"Обнаружена RKN-блокировка (DPI throttle): получено {bytes_received} байт"

    return DiagnosticResult(
        check_name="RKN Throttle",
        status=status,
        severity=CheckSeverity.CRITICAL if status != CheckStatus.PASS else CheckSeverity.INFO,
        message=msg,
        details={
            "target": "test.example.com",
            "total_bytes_received": bytes_received,
            "bytes_received": bytes_received,
            "http_status": 200,
        },
    )


# === Cross-proxy connectivity tests ===


def test_recommendation_blocked_for_direct_connections():
    """Direct FAIL + IP FAIL + Cross PASS → blocked for direct connections."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "IP: 1.2.3.4", server="1.2.3.4"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "заблокирован для прямых подключений" in diag.recommendations[0]
    assert "блокировка для нашей подсети" in diag.recommendations[1]
    assert "сервер рабочий" in diag.recommendations[1]
    assert "мост" in diag.recommendations[2]
    assert "Сменить IP-адрес" in diag.recommendations[2]
    # Check multi-line formatting
    assert "\n" in diag.recommendations[2]


def test_recommendation_domain_level_block():
    """Direct (domain) FAIL + Direct (IP) PASS → domain-level block."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_xray_result(CheckStatus.PASS, "IP: 1.2.3.4", server="1.2.3.4"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "заблокирован (DNS/SNI)" in diag.recommendations[0]
    assert "Заменить домен" in diag.recommendations[2]
    assert "SNI-обфускацию" in diag.recommendations[2]


def test_recommendation_ip_level_block():
    """Direct FAIL + Cross FAIL → IP-level block or server down."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "IP: 1.2.3.4", server="1.2.3.4"))
    diag.add_result(_make_cross_result(CheckStatus.TIMEOUT))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "заблокирован или сервер недоступен" in diag.recommendations[0]
    assert "сменить IP-адрес" in diag.recommendations[2]


# === DNS failure test ===


def test_recommendation_dns_failure():
    """DNS resolution fails → DNS poisoning/geo-blocking recommendation."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))
    diag.add_result(_make_dns_result(CheckStatus.FAIL))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    # DNS check triggers before cross-proxy analysis, so we get DNS recs
    assert len(diag.recommendations) == 3
    assert "DNS" in diag.recommendations[0]
    assert "DNS poisoning" in diag.recommendations[1]
    assert "публичный DNS" in diag.recommendations[2]


# === RKN throttle vs IP block tests ===


def test_recommendation_rkn_throttle_detected():
    """RKN throttle detected (16-20KB) → DPI bypass recommendation.

    Only triggers when Xray connectivity ALSO failed.
    If Xray connectivity passed, this is a different issue (exit IP/SNI).
    """
    # Xray connectivity must fail for RKN throttle recommendations to trigger
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))
    diag.add_result(_make_throttle_result(CheckStatus.FAIL, bytes_received=16_000))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "DPI-троттлинг" in diag.recommendations[0]
    assert "16KB" in diag.recommendations[0]
    assert "обфускацию" in diag.recommendations[2]
    assert "Reality" in diag.recommendations[2]


def test_recommendation_ip_fully_blocked():
    """RKN check timeout (0 bytes) → IP fully blocked recommendation.

    Only triggers when Xray connectivity ALSO failed.
    If Xray connectivity passed, this is exit IP/SNI issue, not IP block.
    """
    # Xray connectivity must fail for IP block recommendations to trigger
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))
    diag.add_result(_make_throttle_result(CheckStatus.FAIL, bytes_received=0))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "заблокирован для прямых подключений" in diag.recommendations[0]
    assert "сервер рабочий" in diag.recommendations[1]
    assert "Сменить IP-адрес" in diag.recommendations[2]
    assert "мост" in diag.recommendations[2]


def test_recommendation_ip_blocked_but_cross_works():
    """IP blocked but cross-proxy works → mention server is OK."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "IP: 1.2.3.4", server="1.2.3.4"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))
    diag.add_result(_make_throttle_result(CheckStatus.FAIL, bytes_received=0))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "сервер рабочий" in diag.recommendations[1]
    assert "только прямые подключения заблокированы" in diag.recommendations[1]


# === Edge cases ===


def test_recommendation_no_cross_proxy_data():
    """No cross-proxy result → no recommendations."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 0


def test_recommendation_direct_passed():
    """Direct passed → no recommendations added."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.PASS, "домен: test.example.com"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 0


def test_recommendation_no_ip_result_but_cross_pass():
    """Direct FAIL + no IP result + Cross PASS → blocked for direct connections."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "заблокирован для прямых подключений" in diag.recommendations[0]


def test_recommendation_deduplicates():
    """Recommendations should not duplicate if function called multiple times."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "домен: test.example.com"))
    diag.add_result(_make_xray_result(CheckStatus.TIMEOUT, "IP: 1.2.3.4", server="1.2.3.4"))
    diag.add_result(_make_cross_result(CheckStatus.PASS))
    # Pre-add a recommendation to test dedup
    diag.add_recommendation("existing")

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)
    analyzer._add_blocking_recommendations(diag)  # call again

    # Should still be 4 (1 existing + 3 new), not more
    assert len(diag.recommendations) == 4


def test_recommendation_exit_ip_sni_failed_but_connectivity_passed():
    """Xray connectivity passed but Exit IP/SNI failed → server routing/firewall issue."""
    diag = HostDiagnostic(host="test.example.com:443")
    diag.add_result(_make_xray_result(CheckStatus.PASS, "домен: test.example.com"))
    # Simulate Exit IP and SNI failures
    diag.add_result(
        DiagnosticResult(
            check_name="Proxy Exit IP (Xray) (домен: test.example.com)",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message="Cannot connect to host api.ipify.org:443",
            details={"protocol": "vless"},
        )
    )
    diag.add_result(
        DiagnosticResult(
            check_name="Proxy SNI Connection (Xray) (домен: test.example.com)",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message="ошибка подключения к max.ru",
            details={"protocol": "vless"},
        )
    )
    diag.add_result(_make_cross_result(CheckStatus.PASS))

    analyzer = XrayAnalyzer()
    analyzer._add_blocking_recommendations(diag)

    assert len(diag.recommendations) == 3
    assert "подключается, но не достигает внешних сервисов" in diag.recommendations[0]
    assert "HTTP 204" in diag.recommendations[1]
    assert "маршрутизацию" in diag.recommendations[2]
    assert "firewall" in diag.recommendations[2]
