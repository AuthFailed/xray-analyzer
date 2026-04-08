"""TCP connection diagnostic checks with timeout and error handling."""

import asyncio

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("tcp_checker")


async def check_tcp_connection(host: str, port: int) -> DiagnosticResult:
    """
    Check TCP connection to host:port with timeout handling.

    Detects:
    - Connection timeouts
    - Connection refused
    - Network unreachable
    - Other connection errors
    """
    start_time = asyncio.get_event_loop().time()
    log.debug("Checking TCP connection", host=host, port=port)

    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=settings.tcp_timeout,
        )
        writer.close()
        await writer.wait_closed()

        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000

        log.info(
            "TCP connection successful",
            host=host,
            port=port,
            duration_ms=round(duration_ms, 2),
        )

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=f"TCP connection to {host}:{port} established successfully",
            details={
                "host": host,
                "port": port,
                "duration_ms": round(duration_ms, 2),
                "timeout_seconds": settings.tcp_timeout,
            },
        )

    except TimeoutError:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error(
            "TCP connection timed out",
            host=host,
            port=port,
            timeout=settings.tcp_timeout,
        )

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"TCP connection to {host}:{port} timed out ({settings.tcp_timeout}s)",
            details={
                "host": host,
                "port": port,
                "timeout_seconds": settings.tcp_timeout,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Сервер не отвечает — проверьте, запущен ли сервис на порту",
                "Проверьте настройки фаервола (iptables, ufw)",
                "Убедитесь, что порт открыт на сервере: netstat -tlnp | grep <порт>",
                "Проверьте сетевую доступность: ping <хост>",
                "Возможно, сервер перегружен или есть сетевые проблемы",
            ],
        )

    except ConnectionRefusedError:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("TCP connection refused", host=host, port=port)

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Connection refused by {host}:{port}",
            details={
                "host": host,
                "port": port,
                "error": "ConnectionRefusedError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                f"Порт {port} закрыт на сервере {host}",
                "Проверьте, запущен ли сервис: systemctl status <сервис>",
                "Проверьте правила фаервола на сервере",
                "Убедитесь, что сервис слушает правильный порт",
                "Проверьте: telnet <хост> <порт> или nc -zv <хост> <порт>",
            ],
        )

    except OSError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        error_str = str(e)
        log.error("TCP connection OS error", host=host, port=port, error=error_str)

        severity, message, recommendations = _handle_os_error(e, host, port)

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.FAIL,
            severity=severity,
            message=message,
            details={
                "host": host,
                "port": port,
                "error_code": e.errno,
                "error_str": error_str,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=recommendations,
        )

    except Exception as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("TCP connection unexpected error", host=host, port=port, error=str(e))

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Unexpected error connecting to {host}:{port}: {e}",
            details={
                "host": host,
                "port": port,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Произошла неожиданная ошибка — проверьте логи системы",
                "Попробуйте повторить попытку",
            ],
        )


def _handle_os_error(
    e: OSError, host: str, port: int
) -> tuple[CheckSeverity, str, list[str]]:
    """Handle specific OSError codes and return severity, message, recommendations."""
    error_code = e.errno

    if error_code == 101:  # Network is unreachable
        return (
            CheckSeverity.CRITICAL,
            f"Network unreachable when connecting to {host}:{port}",
            [
                "Проверьте сетевое подключение",
                "Убедитесь, что маршрут до сети существует: ip route",
                "Проверьте настройки сетевого интерфейса",
                "Попробуйте: ping 8.8.8.8 для проверки интернета",
            ],
        )
    elif error_code == 110:  # Connection timed out
        return (
            CheckSeverity.CRITICAL,
            f"Connection timed out to {host}:{port}",
            [
                "Сервер не отвечает в течение заданного времени",
                "Проверьте настройки фаервола",
                "Убедитесь, что сервер доступен",
            ],
        )
    elif error_code == 111:  # Connection refused (already handled, but fallback)
        return (
            CheckSeverity.ERROR,
            f"Connection refused by {host}:{port}",
            [
                "Порт закрыт — проверьте, запущен ли сервис",
                "Проверьте настройки фаервола",
            ],
        )
    elif error_code == 113:  # No route to host
        return (
            CheckSeverity.CRITICAL,
            f"No route to host {host}:{port}",
            [
                "Нет маршрута до хоста",
                "Проверьте таблицу маршрутизации: ip route",
                "Убедитесь, что хост доступен в сети",
                "Проверьте настройки шлюза",
            ],
        )
    elif error_code in (-2, -3):  # Name resolution errors
        return (
            CheckSeverity.CRITICAL,
            f"DNS resolution failed for {host}",
            [
                "Проверьте настройки DNS-сервера",
                "Попробуйте: dig <домен> или nslookup <домен>",
                "Проверьте /etc/resolv.conf",
            ],
        )
    else:
        return (
            CheckSeverity.ERROR,
            f"OS error connecting to {host}:{port}: {e}",
            [
                f"Код ошибки: {error_code}",
                "Проверьте сетевые настройки и доступность сервера",
            ],
        )
