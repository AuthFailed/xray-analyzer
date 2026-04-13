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

    start_time = asyncio.get_running_loop().time()
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
                message=f"Proxy protocol '{scheme}' not supported for TCP tunnel check",
                details={
                    "proxy_url": proxy_url,
                    "test_url": test_url,
                    "scheme": scheme,
                    "supported_schemes": list(supported_schemes),
                },
                recommendations=[
                    f"Protocol {scheme} is not supported for tunnel check",
                    "Use HTTP or SOCKS proxy for this check",
                ],
            )
    except Exception as e:
        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Invalid proxy URL: {e}",
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
            duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
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
                    message=f"TCP tunnel via proxy working: HTTP {status_code} ({test_url})",
                    details=details,
                )
            else:
                return DiagnosticResult(
                    check_name="Proxy TCP Tunnel",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"TCP tunnel returned unexpected status: HTTP {status_code}",
                    details=details,
                    recommendations=[
                        f"Proxy returned HTTP {status_code} instead of 200/204",
                        "Check that the proxy is working correctly",
                        f"Test URL: {test_url}",
                    ],
                )

    except aiohttp.ClientProxyConnectionError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel connection error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Failed to connect to proxy: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": "ClientProxyConnectionError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Proxy server unavailable or rejecting connections",
                "Check proxy address and port",
                "Make sure proxy is running and listening on the specified port",
            ],
        )

    except aiohttp.ClientConnectorError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel connector error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Connection error through proxy: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": "ClientConnectorError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Error connecting through proxy tunnel",
                "Target server may be unreachable through this proxy",
                "Check proxy network settings",
            ],
        )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel timeout", proxy_url=proxy_url, test_url=test_url)

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"TCP tunnel via proxy timed out ({settings.tcp_timeout}s)",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "timeout_seconds": settings.tcp_timeout,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Proxy not responding within the timeout period",
                "Check that the proxy is running and not overloaded",
                "Proxy may not be able to connect to the target server",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel client error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Error checking TCP tunnel: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "HTTP client error during tunnel check",
                "Check proxy URL validity",
                "For SOCKS proxies make sure aiohttp-socks is installed",
            ],
        )

    except ImportError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel import error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Missing required dependency: {e}",
            details={
                "proxy_url": proxy_url,
                "error": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "SOCKS proxies require the aiohttp-socks package",
                "Install: pip install aiohttp-socks",
            ],
        )

    except Exception as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy TCP tunnel unexpected error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy TCP Tunnel",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Unexpected error checking TCP tunnel: {e}",
            details={
                "proxy_url": proxy_url,
                "test_url": test_url,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "An unexpected error occurred — check logs",
                "Try again",
            ],
        )
