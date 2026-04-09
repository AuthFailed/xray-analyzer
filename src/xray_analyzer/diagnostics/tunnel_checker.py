"""Proxy tunnel diagnostic checks."""

import asyncio
from urllib.parse import urlparse

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("tunnel_checker")

# Protocols that aiohttp can use as HTTP proxy
SUPPORTED_HTTP_PROXY_SCHEMES = {"http", "https", "socks5", "socks5h", "socks4"}


async def check_proxy_tunnel(proxy_url: str, test_url: str | None = None) -> DiagnosticResult:
    """
    Check if traffic is properly routed through the proxy tunnel.

    Only supports HTTP/SOCKS proxy URLs. VLESS, Trojan, Shadowsocks etc.
    are not supported and will be skipped.
    """
    if not settings.tunnel_test_enabled:
        return DiagnosticResult(
            check_name="Proxy Tunnel",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.INFO,
            message="Proxy tunnel check is disabled in configuration",
        )

    # Check if proxy URL is a supported HTTP proxy scheme
    try:
        parsed = urlparse(proxy_url)
        if parsed.scheme.lower() not in SUPPORTED_HTTP_PROXY_SCHEMES:
            return DiagnosticResult(
                check_name="Proxy Tunnel",
                status=CheckStatus.SKIP,
                severity=CheckSeverity.INFO,
                message=f"Protocol '{parsed.scheme}' not supported for tunnel check",
                details={"proxy_url": proxy_url, "protocol": parsed.scheme},
                recommendations=[
                    f"Протокол {parsed.scheme} не поддерживает HTTP-туннель через aiohttp",
                    "Используйте DNS/TCP проверки для диагностики",
                ],
            )
    except Exception:
        return DiagnosticResult(
            check_name="Proxy Tunnel",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.INFO,
            message=f"Invalid proxy URL: {proxy_url}",
        )

    test_url = test_url or settings.tunnel_test_url
    start_time = asyncio.get_event_loop().time()
    log.debug("Checking proxy tunnel", proxy=proxy_url, test_url=test_url)

    try:
        async with aiohttp.ClientSession() as session:
            # Configure proxy
            proxy_auth = None
            proxy_for_request = proxy_url

            # Parse proxy URL for authentication if present
            # Format: protocol://user:pass@host:port or protocol://host:port

            async with session.get(
                test_url,
                proxy=proxy_for_request,
                proxy_auth=proxy_auth,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response:
                duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
                await response.text()

                log.info(
                    "Proxy tunnel check successful",
                    proxy=proxy_url,
                    status_code=response.status,
                    duration_ms=round(duration_ms, 2),
                )

                return DiagnosticResult(
                    check_name="Proxy Tunnel",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=f"Proxy tunnel working through {proxy_url}",
                    details={
                        "proxy_url": proxy_url,
                        "test_url": test_url,
                        "response_status": response.status,
                        "duration_ms": round(duration_ms, 2),
                    },
                )

    except TimeoutError:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("Proxy tunnel check timed out", proxy=proxy_url)

        return DiagnosticResult(
            check_name="Proxy Tunnel",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"Proxy tunnel check timed out for {proxy_url}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Прокси-сервер не отвечает — проверьте его доступность",
                "Убедитесь, что прокси запущен и работает",
                "Проверьте настройки прокси в конфигурации Xray",
            ],
        )

    except aiohttp.ClientProxyConnectionError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error(
            "Proxy connection error",
            proxy=proxy_url,
            error=str(e),
        )

        return DiagnosticResult(
            check_name="Proxy Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Failed to connect through proxy {proxy_url}: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Проверьте настройки прокси-сервера",
                "Убедитесь, что прокси доступен по указанному URL",
                "Проверьте аутентификационные данные прокси",
                "Проверьте конфигурацию Xray для данного прокси",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error(
            "Proxy tunnel HTTP error",
            proxy=proxy_url,
            error=str(e),
        )

        return DiagnosticResult(
            check_name="Proxy Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"HTTP error through proxy {proxy_url}: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Ошибка при подключении через прокси",
                "Проверьте URL прокси и тестовый URL",
                "Попробуйте другой тестовый URL",
            ],
        )

    except Exception as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error(
            "Proxy tunnel unexpected error",
            proxy=proxy_url,
            error=str(e),
        )

        return DiagnosticResult(
            check_name="Proxy Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Unexpected error checking proxy tunnel: {e}",
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
