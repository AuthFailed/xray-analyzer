"""Cross-proxy diagnostic: test connectivity to a target through another proxy."""

import asyncio
from ipaddress import ip_address

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL
from xray_analyzer.diagnostics.xray_manager import XrayInstance

log = get_logger("proxy_cross_checker")


async def check_via_proxy(
    target_host: str,
    target_port: int,
    proxy_url: str,
    proxy_name: str = "",
) -> DiagnosticResult:
    """
    Test TCP connectivity to target_host:target_port through a proxy.

    This helps determine if the issue is with the target server itself
    or with the local network/infrastructure.

    Args:
        target_host: Target hostname or IP
        target_port: Target port
        proxy_url: Proxy URL (http:// or socks5://)
        proxy_name: Human-readable proxy name for messages

    Returns:
        DiagnosticResult with connectivity status.
    """
    start_time = asyncio.get_running_loop().time()

    # Use the status check URL as a connectivity probe through the target
    test_url = settings.proxy_status_check_url

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                test_url,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as response,
        ):
            duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            status_code = response.status

            if status_code in (200, 204):
                return DiagnosticResult(
                    check_name="Cross-Proxy Connectivity",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=(
                        f"Доступен через {proxy_name}: "
                        f"{target_host}:{target_port} → HTTP {status_code}, "
                        f"{round(duration_ms)}ms"
                    ),
                    details={
                        "target_host": target_host,
                        "target_port": target_port,
                        "proxy_name": proxy_name,
                        "http_status": status_code,
                        "duration_ms": round(duration_ms, 2),
                    },
                )
            else:
                return DiagnosticResult(
                    check_name="Cross-Proxy Connectivity",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.WARNING,
                    message=f"HTTP {status_code} через {proxy_name}",
                    details={
                        "target_host": target_host,
                        "target_port": target_port,
                        "proxy_name": proxy_name,
                        "http_status": status_code,
                        "duration_ms": round(duration_ms, 2),
                    },
                )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name="Cross-Proxy Connectivity",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"Таймаут через {proxy_name}",
            details={
                "target_host": target_host,
                "target_port": target_port,
                "proxy_name": proxy_name,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Сервер недоступен даже через другой рабочий прокси",
                "Возможно, сервер выключен или заблокирован на уровне сети",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name="Cross-Proxy Connectivity",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Ошибка через {proxy_name} — {e}",
            details={
                "target_host": target_host,
                "target_port": target_port,
                "proxy_name": proxy_name,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Не удалось подключиться через рабочий прокси",
                "Сервер может быть недоступен или заблокирован",
            ],
        )


async def check_xray_cross_connectivity(
    target_host: str,
    target_port: int,
    target_protocol: str,
    working_proxy_share: ProxyShareURL,
    working_proxy_name: str = "",
) -> DiagnosticResult:
    """
    Test connectivity to a problematic server through another working Xray proxy.

    This determines if the server is blocked from our location or if it's
    down entirely. If the server is reachable through another proxy, it's
    likely blocked by RKN. If it also fails through the working proxy,
    the server itself is having issues.

    Args:
        target_host: Problematic server hostname or IP
        target_port: Problematic server port
        target_protocol: Protocol of the problematic server (e.g. vless)
        working_proxy_share: Share URL of the working Xray proxy
        working_proxy_name: Human-readable name of the working proxy

    Returns:
        DiagnosticResult with cross-connectivity status.
    """
    start_time = asyncio.get_running_loop().time()
    log.info(
        f"Cross-test: checking {target_host}:{target_port} via {working_proxy_name} ({working_proxy_share.protocol})"
    )

    xray = XrayInstance(working_proxy_share)
    socks_port = 0
    xray_started = False

    try:
        socks_port = await xray.start()
        xray_started = True
    except RuntimeError as e:
        log.error(f"Failed to start working Xray proxy for cross-test: {e}")
        return DiagnosticResult(
            check_name="Xray Cross-Proxy Connectivity",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.WARNING,
            message=f"Не удалось запустить рабочий прокси для проверки: {e}",
            details={
                "target_host": target_host,
                "target_port": target_port,
                "target_protocol": target_protocol,
                "working_proxy": working_proxy_name,
                "error": str(e),
            },
        )

    socks_url = f"socks5://127.0.0.1:{socks_port}"

    try:
        # Test connectivity to the target server through the working proxy
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    settings.proxy_status_check_url,
                    proxy=socks_url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as response:
                    duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
                    status_code = response.status

                    if status_code in (200, 204):
                        return DiagnosticResult(
                            check_name="Xray Cross-Proxy Connectivity",
                            status=CheckStatus.PASS,
                            severity=CheckSeverity.INFO,
                            message=(
                                f"✓ Сервер доступен через {working_proxy_name}: "
                                f"HTTP {status_code}, {round(duration_ms)}ms"
                            ),
                            details={
                                "target_host": target_host,
                                "target_port": target_port,
                                "target_protocol": target_protocol,
                                "working_proxy": working_proxy_name,
                                "working_proxy_protocol": working_proxy_share.protocol,
                                "http_status": status_code,
                                "duration_ms": round(duration_ms, 2),
                                "recommendations": [
                                    "Сервер доступен через другой рабочий прокси",
                                    "Возможно, сервер заблокирован (RKN) или недоступен из вашего местоположения",
                                    "Попробуйте использовать другой сервер из подписки",
                                ],
                            },
                        )
                    else:
                        return DiagnosticResult(
                            check_name="Xray Cross-Proxy Connectivity",
                            status=CheckStatus.FAIL,
                            severity=CheckSeverity.WARNING,
                            message=f"HTTP {status_code} через {working_proxy_name}",
                            details={
                                "target_host": target_host,
                                "target_port": target_port,
                                "target_protocol": target_protocol,
                                "working_proxy": working_proxy_name,
                                "working_proxy_protocol": working_proxy_share.protocol,
                                "http_status": status_code,
                                "duration_ms": round(duration_ms, 2),
                            },
                        )

            except TimeoutError:
                duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
                return DiagnosticResult(
                    check_name="Xray Cross-Proxy Connectivity",
                    status=CheckStatus.TIMEOUT,
                    severity=CheckSeverity.CRITICAL,
                    message=f"Таймаут через {working_proxy_name}",
                    details={
                        "target_host": target_host,
                        "target_port": target_port,
                        "target_protocol": target_protocol,
                        "working_proxy": working_proxy_name,
                        "working_proxy_protocol": working_proxy_share.protocol,
                        "duration_ms": round(duration_ms, 2),
                        "recommendations": [
                            "Сервер недоступен даже через другой рабочий прокси",
                            "Возможно, сервер выключен или заблокирован на уровне сети",
                            "Проверьте статус сервера на других ресурсах",
                        ],
                    },
                )

            except aiohttp.ClientError as e:
                duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
                return DiagnosticResult(
                    check_name="Xray Cross-Proxy Connectivity",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.CRITICAL,
                    message=f"Ошибка через {working_proxy_name} — {e}",
                    details={
                        "target_host": target_host,
                        "target_port": target_port,
                        "target_protocol": target_protocol,
                        "working_proxy": working_proxy_name,
                        "working_proxy_protocol": working_proxy_share.protocol,
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "duration_ms": round(duration_ms, 2),
                    },
                    recommendations=[
                        "Не удалось подключиться через рабочий прокси",
                        "Сервер может быть недоступен или заблокирован",
                    ],
                )
    finally:
        if xray_started:
            await xray.stop()


def _is_ipv4(s: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        return ip_address(s).version == 4
    except ValueError:
        return False
