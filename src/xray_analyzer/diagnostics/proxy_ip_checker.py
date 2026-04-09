"""Proxy exit IP address check."""

import asyncio
from urllib.parse import urlparse

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("proxy_ip_checker")


async def check_proxy_exit_ip(
    proxy_url: str,
    ip_check_url: str | None = None,
) -> DiagnosticResult:
    """
    Check the exit IP address when connecting through a proxy.

    Uses PROXY_IP_CHECK_URL (default: https://api.ipify.org?format=text)
    to determine what IP address the proxy exits to the internet with.

    This helps verify:
    - Proxy is working and routing traffic
    - The IP address matches expected location/region
    - Proxy isn't leaking real IP

    Args:
        proxy_url: Full proxy URL (protocol://server:port)
        ip_check_url: URL that returns plain text IP (defaults to settings.proxy_ip_check_url)
    """
    if ip_check_url is None:
        ip_check_url = settings.proxy_ip_check_url

    start_time = asyncio.get_event_loop().time()
    log.debug("Checking proxy exit IP", proxy_url=proxy_url, ip_check_url=ip_check_url)

    # Check if proxy scheme is supported
    supported_schemes = {"http", "https", "socks5", "socks5h", "socks4"}
    try:
        parsed_proxy = urlparse(proxy_url)
        scheme = parsed_proxy.scheme.lower()
        if scheme not in supported_schemes:
            return DiagnosticResult(
                check_name="Proxy Exit IP",
                status=CheckStatus.SKIP,
                severity=CheckSeverity.INFO,
                message=f"Протокол прокси '{scheme}' не поддерживается для Exit IP check",
                details={
                    "proxy_url": proxy_url,
                    "scheme": scheme,
                    "supported_schemes": list(supported_schemes),
                },
            )
    except Exception as e:
        return DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Некорректный URL прокси: {e}",
            details={"proxy_url": proxy_url, "error": str(e)},
        )

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                ip_check_url,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response,
        ):
            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000

            if response.status != 200:
                return DiagnosticResult(
                    check_name="Proxy Exit IP",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"IP check вернул HTTP {response.status}",
                    details={
                        "proxy_url": proxy_url,
                        "ip_check_url": ip_check_url,
                        "http_status": response.status,
                        "duration_ms": round(duration_ms, 2),
                    },
                )

            exit_ip = (await response.text()).strip()

            details = {
                "proxy_url": proxy_url,
                "ip_check_url": ip_check_url,
                "exit_ip": exit_ip,
                "proxy_scheme": scheme,
                "duration_ms": round(duration_ms, 2),
            }

            log.info(
                "Proxy exit IP check successful",
                proxy_url=proxy_url,
                exit_ip=exit_ip,
                duration_ms=round(duration_ms, 2),
            )

            return DiagnosticResult(
                check_name="Proxy Exit IP",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"Exit IP через прокси: {exit_ip}",
                details=details,
            )

    except aiohttp.ClientProxyConnectionError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy exit IP connection error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Не удалось подключиться к прокси: {e}",
            details={
                "proxy_url": proxy_url,
                "ip_check_url": ip_check_url,
                "error": str(e),
                "error_type": "ClientProxyConnectionError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Прокси-сервер недоступен",
                "Проверьте адрес и порт прокси",
                "Убедитесь, что прокси запущен",
            ],
        )

    except aiohttp.ClientConnectorError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy exit IP connector error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Ошибка подключения через прокси: {e}",
            details={
                "proxy_url": proxy_url,
                "ip_check_url": ip_check_url,
                "error": str(e),
                "error_type": "ClientConnectorError",
                "duration_ms": round(duration_ms, 2),
            },
        )

    except TimeoutError:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy exit IP timeout", proxy_url=proxy_url)

        return DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message="Превышено время ожидания проверки Exit IP (15s)",
            details={
                "proxy_url": proxy_url,
                "ip_check_url": ip_check_url,
                "timeout_seconds": 15,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Прокси не отвечает в течение заданного таймаута",
                "Проверьте, что прокси запущен и не перегружен",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy exit IP client error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Ошибка при проверке Exit IP: {e}",
            details={
                "proxy_url": proxy_url,
                "ip_check_url": ip_check_url,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Для SOCKS прокси убедитесь, что установлен aiohttp-socks",
                "Проверьте корректность URL прокси",
            ],
        )

    except ImportError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy exit IP import error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Отсутствует необходимая зависимость: {e}",
            details={
                "proxy_url": proxy_url,
                "error": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Для SOCKS прокси требуется пакет aiohttp-socks",
                "Установите: pip install aiohttp-socks",
            ],
        )

    except Exception as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy exit IP unexpected error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy Exit IP",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Неожиданная ошибка при проверке Exit IP: {e}",
            details={
                "proxy_url": proxy_url,
                "ip_check_url": ip_check_url,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
        )
