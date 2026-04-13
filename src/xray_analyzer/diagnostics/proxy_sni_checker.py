"""Proxy SNI (Server Name Indication) connection check."""

import asyncio
import ssl
from urllib.parse import urlparse

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("proxy_sni_checker")


async def check_proxy_sni_connection(
    proxy_url: str,
    sni_domain: str | None = None,
) -> DiagnosticResult:
    """
    Check if proxy can connect to a known non-blocked SNI domain.

    Uses a 100% non-blocked SNI domain (default: max.ru) to verify:
    - Proxy can establish TLS connections
    - Proxy is not being MITM'd (TLS interception)
    - Proxy can reach Russian/non-blocked domains

    This check is useful to distinguish between:
    - Proxy being blocked vs specific destination being blocked
    - TLS interception by proxy/provider

    Args:
        proxy_url: Full proxy URL (protocol://server:port)
        sni_domain: Domain to test through proxy (default: settings.proxy_sni_domain = max.ru)
    """
    if sni_domain is None:
        sni_domain = settings.proxy_sni_domain

    start_time = asyncio.get_running_loop().time()
    log.debug("Checking proxy SNI connection", proxy_url=proxy_url, sni_domain=sni_domain)

    # Check if proxy scheme is supported
    supported_schemes = {"http", "https", "socks5", "socks5h", "socks4"}
    try:
        parsed_proxy = urlparse(proxy_url)
        scheme = parsed_proxy.scheme.lower()
        if scheme not in supported_schemes:
            return DiagnosticResult(
                check_name="Proxy SNI Connection",
                status=CheckStatus.SKIP,
                severity=CheckSeverity.INFO,
                message=f"Proxy protocol '{scheme}' not supported for SNI check",
                details={
                    "proxy_url": proxy_url,
                    "sni_domain": sni_domain,
                    "scheme": scheme,
                    "supported_schemes": list(supported_schemes),
                },
            )
    except Exception as e:
        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Invalid proxy URL: {e}",
            details={"proxy_url": proxy_url, "error": str(e)},
        )

    test_url = f"https://{sni_domain}"

    try:
        async with aiohttp.ClientSession() as session:
            # Create SSL context that verifies certificate and uses SNI
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            async with session.get(
                test_url,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=ssl_context,
                allow_redirects=True,
            ) as response:
                duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
                status_code = response.status

                # Get SSL/TLS info if available
                ssl_info = {}
                if response.connection and response.connection.transport:
                    try:
                        ssl_obj = response.connection.transport.get_extra_info("ssl_object")
                        if ssl_obj:
                            ssl_info = {
                                "cipher": ssl_obj.cipher()[0] if ssl_obj.cipher() else None,
                                "version": ssl_obj.version(),
                            }
                    except Exception:
                        pass

                details = {
                    "proxy_url": proxy_url,
                    "sni_domain": sni_domain,
                    "test_url": test_url,
                    "http_status": status_code,
                    "proxy_scheme": scheme,
                    "duration_ms": round(duration_ms, 2),
                    "ssl_info": ssl_info,
                }

                log.info(
                    "Proxy SNI connection check",
                    proxy_url=proxy_url,
                    sni_domain=sni_domain,
                    status=status_code,
                    duration_ms=round(duration_ms, 2),
                )

                # 200, 204, 301, 302, 304 are acceptable responses
                if status_code in (200, 204, 301, 302, 304):
                    return DiagnosticResult(
                        check_name="Proxy SNI Connection",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message=f"Proxy connected to {sni_domain} (SNI): HTTP {status_code}",
                        details=details,
                    )
                else:
                    return DiagnosticResult(
                        check_name="Proxy SNI Connection",
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.WARNING,
                        message=f"Proxy returned unexpected status for {sni_domain}: HTTP {status_code}",
                        details=details,
                        recommendations=[
                            f"Proxy returned HTTP {status_code} for {sni_domain}",
                            f"{sni_domain} is a known non-blocked domain, issue may be on the proxy side",
                        ],
                    )

    except aiohttp.ClientProxyConnectionError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy SNI connection error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Failed to connect to proxy for SNI check: {e}",
            details={
                "proxy_url": proxy_url,
                "sni_domain": sni_domain,
                "error": str(e),
                "error_type": "ClientProxyConnectionError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Proxy server unavailable",
                "Check proxy address and port",
                "Make sure the proxy is running",
            ],
        )

    except aiohttp.ClientConnectorCertificateError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy SNI certificate error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"SSL certificate error when connecting through proxy: {e}",
            details={
                "proxy_url": proxy_url,
                "sni_domain": sni_domain,
                "error": str(e),
                "error_type": "ClientConnectorCertificateError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Possible MITM attack (TLS interception) at proxy level",
                "Proxy may be substituting SSL certificates",
                "Use a different proxy or check its settings",
            ],
        )

    except aiohttp.ClientConnectorSSLError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy SNI SSL error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"SSL error when connecting through proxy: {e}",
            details={
                "proxy_url": proxy_url,
                "sni_domain": sni_domain,
                "error": str(e),
                "error_type": "ClientConnectorSSLError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "SSL connection error through proxy",
                "Proxy may be blocking or modifying TLS connections",
                "Check if the proxy supports TLS tunneling",
            ],
        )

    except aiohttp.ClientConnectorError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy SNI connector error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Connection error through proxy to {sni_domain}: {e}",
            details={
                "proxy_url": proxy_url,
                "sni_domain": sni_domain,
                "error": str(e),
                "error_type": "ClientConnectorError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                f"Could not connect to {sni_domain} through proxy",
                "Domain may be blocked or proxy cannot establish connection",
                "Check proxy network settings",
            ],
        )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy SNI timeout", proxy_url=proxy_url, sni_domain=sni_domain)

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"Connection to {sni_domain} through proxy timed out (15s)",
            details={
                "proxy_url": proxy_url,
                "sni_domain": sni_domain,
                "timeout_seconds": 15,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                f"Proxy cannot connect to {sni_domain} within the timeout period",
                f"{sni_domain} is a non-blocked domain — issue is on the proxy side",
                "Check that the proxy is running and not overloaded",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy SNI client error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Error checking SNI through proxy: {e}",
            details={
                "proxy_url": proxy_url,
                "sni_domain": sni_domain,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "For SOCKS proxies make sure aiohttp-socks is installed",
                "Check proxy URL validity",
            ],
        )

    except ImportError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("Proxy SNI import error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
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
        log.error("Proxy SNI unexpected error", proxy_url=proxy_url, error=str(e))

        return DiagnosticResult(
            check_name="Proxy SNI Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Unexpected error checking SNI: {e}",
            details={
                "proxy_url": proxy_url,
                "sni_domain": sni_domain,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "An unexpected error occurred — check logs",
                "Try again",
            ],
        )
