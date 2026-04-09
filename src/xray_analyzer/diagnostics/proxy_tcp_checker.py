"""Proxy TCP tunnel check through proxy to status URL."""

import asyncio
from typing import Any
from urllib.parse import urlparse

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("proxy_tcp_checker")


async def check_proxy_tcp_tunnel(
    proxy_url: str,
    test_url: str | None = None,
) -> DiagnosticResult:
    """
    Check TCP tunnel through proxy to a status check URL.

    Uses PROXY_STATUS_CHECK_URL (default: http://cp.cloudflare.com/generate_204)
    to verify that the proxy can establish a working tunnel.

    Supports HTTP and SOCKS proxies (http, https, socks5, socks5h, socks4).
    VLESS, Trojan, Shadowsocks and other protocols are skipped.

    Args:
        proxy_url: Full proxy URL (protocol://server:port)
        test_url: URL to test through the proxy (defaults to settings.proxy_status_check_url)
    """
    if test_url is None:
        test_url = settings.proxy_status_check_url

    start_time = asyncio.get_event_loop().time()
    log.debug("Checking proxy TCP tunnel", proxy_url=proxy_url, test_url=test_url)

    # Check if proxy scheme is supported for tunnel test
    supported_schemes = {"http", "https", "socks5", "socks5h", "socks4"}
    try:
        parsed_proxy = urlparse(proxy_url)
        scheme = parsed_proxy.scheme.lower()
        if scheme not in supported_schemes:
            return DiagnosticResult(
                check_name="Proxy TCP Tunnel",
                status=CheckStatus.SKIP,
                severity=CheckSeverity.INFO,
                message=f"Протокол прокси '{scheme}' не поддерживается для TCP tunnel check",
                details={
                    "proxy_url": proxy_url,
                    "test_url": test_url,
                    "scheme": scheme,
                    "supported_schemes": list(supported_schemes),
                },
                recommendations=[
                    f"Протокол {scheme} не поддерживается для туннельной проверки",
                    "Используйте HTTP или SOCKS прокси для данной проверки",
                ],
            )
    except Exception as e:
        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Некорректный URL прокси: {e}",
            details={"proxy_url": proxy_url, "error": str(e)},
        )

    try:
        # For SOCKS proxies, aiohttp needs aiohttp_socks_proxy
        proxy_for_request = proxy_url

        async with (
            aiohttp.ClientSession() as session,
            session.get(
                test_url,
                proxy=proxy_for_request,
                timeout=aiohttp.ClientTimeout(total=settings.tcp_timeout),
                allow_redirects=True,
            ) as response,
        ):
            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            status_code = response.status

            details: dict[str, Any] = {
                "proxy_url": proxy_url,
                "test_url": test_url,
                "http_status": status_code,
                "duration_ms": round(duration_ms, 2),
                "proxy_scheme": scheme,
            }

            log.info(
                "Proxy TCP tunnel check",
                proxy_url=proxy_url,
                test_url=test_url,
                status=status_code,
                duration_ms=round(duration_ms, 2),
            )

            # 204 or 200 are success
            if status_code in (200, 204):
                return DiagnosticResult(
                    check_name="Proxy TCP Tunnel",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=f"TCP tunnel через прокси работает: HTTP {status_code} ({test_url})",
                    details=details,
                )
            else:
                return DiagnosticResult(
                    check_name="Proxy TCP Tunnel",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"TCP tunnel вернул неожиданный статус: HTTP {status_code}",
                    details=details,
                    recommendations=[
                        f"Прокси вернул HTTP {status_code} вместо 200/204",
                        "Проверьте, что прокси работает корректно",
                        f"Тестовый URL: {test_url}",
                    ],
                )

    except aiohttp.ClientProxyConnectionError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel connection error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Не удалось подключиться к прокси: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": "ClientProxyConnectionError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Прокси-сервер недоступен или отклоняет подключение",
                "Проверьте адрес и порт прокси",
                "Убедитесь, что прокси запущен и слушает указанный порт",
            ],
        )

    except aiohttp.ClientConnectorError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel connector error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Ошибка подключения через прокси: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": "ClientConnectorError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Ошибка при подключении через прокси-туннель",
                "Возможно, целевой сервер недоступен через данный прокси",
                "Проверьте сетевые настройки прокси",
            ],
        )

    except TimeoutError:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel timeout", proxy_url=proxy_url, test_url=test_url)

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"Превышено время ожидания TCP tunnel через прокси ({settings.tcp_timeout}s)",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "timeout_seconds": settings.tcp_timeout,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Прокси не отвечает в течение заданного таймаута",
                "Проверьте, что прокси запущен и не перегружен",
                "Возможно, прокси не может установить соединение с целевым сервером",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel client error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Ошибка при проверке TCP tunnel: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Ошибка HTTP клиента при проверке туннеля",
                "Проверьте корректность URL прокси",
                "Для SOCKS прокси убедитесь, что установлен aiohttp-socks",
            ],
        )

    except ImportError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel import error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
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
        log.error("Proxy TCP tunnel unexpected error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Неожиданная ошибка при проверке TCP tunnel: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Произошла неожиданная ошибка — проверьте логи",
                "Попробуйте повторить попытку",
            ],
        )
