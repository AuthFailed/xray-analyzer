"""Tests for Telegram notifier formatting."""

from xray_analyzer.core.models import (
    CheckSeverity,
    CheckStatus,
    DiagnosticResult,
    HostDiagnostic,
)
from xray_analyzer.notifiers.telegram import (
    TelegramNotifier,
    _format_check_result,
    _format_recommendations,
    _format_tcp_ping,
)


class TestFormatTcpPing:
    """Test TCP ping formatting."""

    def test_good_ping(self):
        details = {"latency_avg_ms": 45.0, "packet_loss_pct": 0}
        result = _format_tcp_ping(details)
        assert "✓" in result
        assert "45ms" in result

    def test_medium_ping(self):
        details = {"latency_avg_ms": 150.0, "packet_loss_pct": 0}
        result = _format_tcp_ping(details)
        assert "150ms" in result
        assert "✓" not in result  # Not marked as good

    def test_high_ping(self):
        details = {"latency_avg_ms": 350.0, "packet_loss_pct": 0}
        result = _format_tcp_ping(details)
        assert "🟡" in result
        assert "высокий" in result
        assert "350ms" in result

    def test_packet_loss_low(self):
        details = {"latency_avg_ms": 100.0, "packet_loss_pct": 10}
        result = _format_tcp_ping(details)
        assert "10%" in result
        assert "потери" in result

    def test_packet_loss_medium(self):
        details = {"latency_avg_ms": 200.0, "packet_loss_pct": 30}
        result = _format_tcp_ping(details)
        assert "🟡" in result
        assert "потери 30%" in result

    def test_packet_loss_critical(self):
        details = {"latency_avg_ms": 500.0, "packet_loss_pct": 75}
        result = _format_tcp_ping(details)
        assert "🔴" in result
        assert "критические потери 75%" in result

    def test_no_data(self):
        details = {}
        result = _format_tcp_ping(details)
        assert result == "нет данных"


class TestFormatCheckResult:
    """Test check result formatting."""

    def test_passed_dns_resolution(self):
        check = DiagnosticResult(
            check_name="DNS Resolution (Check-Host)",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message="DNS resolved",
            details={
                "local_ips": ["1.2.3.4"],
                "checkhost_ips": ["1.2.3.4"],
            },
        )
        result = _format_check_result(check)
        assert result is not None
        assert isinstance(result, list)
        assert "DNS разрешён" in result[0]
        assert "Локальный DNS: 1.2.3.4" in result[1]
        assert "Check-Host: 1.2.3.4" in result[2]

    def test_passed_tcp_ping(self):
        check = DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message="Ping successful",
            details={"latency_avg_ms": 50.0, "packet_loss_pct": 0},
        )
        result = _format_check_result(check)
        assert result is not None
        assert isinstance(result, str)
        assert "✓" in result
        assert "50ms" in result

    def test_passed_tcp_connection(self):
        check = DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message="Connection successful",
            details={},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "TCP-соединения" in result

    def test_passed_cross_proxy(self):
        check = DiagnosticResult(
            check_name="Xray Cross-Proxy Connectivity",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message="Сервер доступен через Польша",
            details={
                "working_proxy": "🇵🇱 Польша",
                "working_proxy_protocol": "vless",
            },
        )
        result = _format_check_result(check)
        assert result is not None
        assert "🇵🇱 Польша" in result
        assert "Xray" in result
        assert "сервер работает, возможна блокировка" in result

    def test_failed_cross_proxy(self):
        check = DiagnosticResult(
            check_name="Xray Cross-Proxy Connectivity",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.WARNING,
            message="Таймаут через Финляндия",
            details={
                "working_proxy": "🇫🇮 Финляндия",
                "working_proxy_protocol": "vless",
            },
        )
        result = _format_check_result(check)
        assert result is not None
        assert "🇫🇮 Финляндия" in result
        assert "сервер может быть выключен" in result

    def test_passed_exit_ip(self):
        check = DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message="Exit IP determined",
            details={"exit_ip": "1.2.3.4"},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "1.2.3.4" in result

    def test_passed_rkn(self):
        check = DiagnosticResult(
            check_name="RKN Block Check",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message="Not blocked",
            details={},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "не заблокирован" in result

    def test_failed_xray_connectivity(self):
        check = DiagnosticResult(
            check_name="Proxy Xray Connectivity",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message="Connection timeout after 10s",
            details={"protocol": "vless", "timeout_seconds": 10},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "❌" in result
        assert "vless" in result
        assert "основная проверка через Xray" in result

    def test_failed_xray_connectivity_with_fallback(self):
        check = DiagnosticResult(
            check_name="Proxy Xray Connectivity (IP: 1.2.3.4)",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.ERROR,
            message="Connection timeout",
            details={"protocol": "vless"},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "⏱" in result
        assert "fallback по IP" in result
        assert "основной тест по домену не прошёл" in result

    def test_failed_check(self):
        check = DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message="Connection refused",
            details={"protocol": "vless"},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "❌" in result

    def test_timeout_check(self):
        check = DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.ERROR,
            message="Connection timed out",
            details={"timeout_seconds": 5},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "⏱" in result

    def test_skipped_check(self):
        check = DiagnosticResult(
            check_name="Legacy Tunnel Test",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.WARNING,
            message="Not applicable",
            details={},
        )
        result = _format_check_result(check)
        assert result is not None
        assert "○" in result
        assert "пропущено" in result


class TestFormatRecommendations:
    """Test recommendations formatting."""

    def test_with_recommendations(self):
        diag = HostDiagnostic(host="example.com:443")
        diag.add_result(
            DiagnosticResult(
                check_name="Proxy Xray Connectivity",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.ERROR,
                message="Failed",
                recommendations=["Check proxy settings", "Verify subscription"],
            )
        )
        diag.add_recommendation("Run analyzer for details")

        result = _format_recommendations(diag)
        assert "🔧" in result
        assert "Check proxy settings" in result

    def test_no_recommendations(self):
        diag = HostDiagnostic(host="example.com:443")
        result = _format_recommendations(diag)
        assert result == ""

    def test_deduplicates_recommendations(self):
        diag = HostDiagnostic(host="example.com:443")
        diag.add_result(
            DiagnosticResult(
                check_name="Check 1",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.ERROR,
                message="Failed",
                recommendations=["Same recommendation"],
            )
        )
        diag.add_result(
            DiagnosticResult(
                check_name="Check 2",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.ERROR,
                message="Failed",
                recommendations=["Same recommendation"],
            )
        )

        result = _format_recommendations(diag)
        # Should appear only once
        assert result.count("Same recommendation") == 1

    def test_limits_to_3_recommendations(self):
        diag = HostDiagnostic(host="example.com:443")
        for i in range(5):
            diag.add_result(
                DiagnosticResult(
                    check_name=f"Check {i}",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"Failed {i}",
                    recommendations=[f"Recommendation {i}"],
                )
            )

        result = _format_recommendations(diag)
        count = result.count("🔧")
        assert count <= 3


class TestTelegramNotifierBuildMessage:
    """Test Telegram notifier message building."""

    def test_build_message_with_problematic(self):
        notifier = TelegramNotifier()

        all_diagnostics = [
            HostDiagnostic(
                host="proxy1.example.com:443",
                overall_status=CheckStatus.FAIL,
                results=[
                    DiagnosticResult(
                        check_name="TCP Ping",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message="Ping successful",
                        details={"latency_avg_ms": 50.0, "packet_loss_pct": 0},
                    ),
                    DiagnosticResult(
                        check_name="Proxy Xray Connectivity",
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.ERROR,
                        message="Connection timeout",
                        details={"protocol": "vless"},
                        recommendations=["Check settings"],
                    ),
                ],
            ),
            HostDiagnostic(
                host="proxy2.example.com:443",
                overall_status=CheckStatus.PASS,
                results=[
                    DiagnosticResult(
                        check_name="TCP Ping",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message="Ping successful",
                        details={"latency_avg_ms": 30.0, "packet_loss_pct": 0},
                    ),
                ],
            ),
        ]

        problematic = [d for d in all_diagnostics if d.overall_status != CheckStatus.PASS]
        message = notifier._build_message(problematic, all_diagnostics)

        assert "proxy1.example.com:443" in message
        assert "proxy2" not in message  # Should not include passing host
        assert "Тесты:" in message
        assert "Что проверить:" in message

    def test_message_structure(self):
        notifier = TelegramNotifier()

        diag = HostDiagnostic(
            host="test.host:443",
            overall_status=CheckStatus.FAIL,
            results=[
                DiagnosticResult(
                    check_name="DNS Resolution",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message="Resolved",
                    details={},
                ),
                DiagnosticResult(
                    check_name="TCP Connection",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message="Connection refused",
                    details={},
                ),
            ],
        )

        message = notifier._build_message([diag], [diag])

        # Check structure
        assert "Xray Analyzer" in message
        assert "test.host:443" in message
        assert "1." in message  # Numbered list
        assert "Тесты:" in message

    def test_message_truncation(self):
        notifier = TelegramNotifier()

        # Create a diagnostic with very long messages
        results = []
        for i in range(50):
            results.append(
                DiagnosticResult(
                    check_name=f"Check {i}",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message="A" * 200,
                    details={},
                )
            )

        diag = HostDiagnostic(
            host="long.host:443",
            overall_status=CheckStatus.FAIL,
            results=results,
        )

        message = notifier._build_message([diag], [diag])

        # Should be truncated
        assert len(message) <= 4050  # MAX_MESSAGE_LENGTH + small buffer
        assert "обрезано" in message or len(message) < 10000
