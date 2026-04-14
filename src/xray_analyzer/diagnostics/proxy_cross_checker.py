"""Cross-proxy diagnostic: test connectivity to a target through another proxy."""

import asyncio

import aiohttp

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

    Connects to the target via the given HTTP/SOCKS proxy to determine
    whether the target is reachable from a different network path.
    Any TCP-level response (including non-HTTP) is treated as success.

    Args:
        target_host: Target hostname or IP
        target_port: Target port
        proxy_url: Proxy URL (http:// or socks5://)
        proxy_name: Human-readable proxy name for messages
    """
    loop = asyncio.get_running_loop()
    start_time = loop.time()

    # Use http:// to establish a raw TCP connection through the proxy.
    # The target is a proxy server (not HTTP), so it will likely disconnect
    # or respond with protocol noise — both confirm TCP connectivity.
    test_url = f"http://{target_host}:{target_port}/"

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                test_url,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=15, connect=10),
                allow_redirects=False,
            ) as response,
        ):
            duration_ms = (loop.time() - start_time) * 1000
            return DiagnosticResult(
                check_name="Cross-Proxy Connectivity",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=(
                    f"Доступен через {proxy_name}: "
                    f"{target_host}:{target_port} → HTTP {response.status}, "
                    f"{round(duration_ms)}ms"
                ),
                details={
                    "target_host": target_host,
                    "target_port": target_port,
                    "proxy_name": proxy_name,
                    "http_status": response.status,
                    "duration_ms": round(duration_ms, 2),
                },
            )

    except aiohttp.ServerDisconnectedError:
        # Server disconnected after TCP connect — target is not HTTP but TCP succeeded
        duration_ms = (loop.time() - start_time) * 1000
        return DiagnosticResult(
            check_name="Cross-Proxy Connectivity",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=(
                f"Доступен через {proxy_name}: {target_host}:{target_port} — TCP подключение установлено, "
                f"{round(duration_ms)}ms"
            ),
            details={
                "target_host": target_host,
                "target_port": target_port,
                "proxy_name": proxy_name,
                "duration_ms": round(duration_ms, 2),
            },
        )

    except TimeoutError:
        duration_ms = (loop.time() - start_time) * 1000
        return DiagnosticResult(
            check_name="Cross-Proxy Connectivity",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"Таймаут через {proxy_name}: {target_host}:{target_port}",
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
        duration_ms = (loop.time() - start_time) * 1000
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

    Launches the working proxy and tries to reach target_host:target_port through
    its SOCKS tunnel. If reachable, the target is likely RKN-blocked from our
    location but works elsewhere. If unreachable through the proxy too, the server
    itself is down.

    Args:
        target_host: Problematic server hostname or IP
        target_port: Problematic server port
        target_protocol: Protocol of the problematic server (e.g. vless)
        working_proxy_share: Share URL of the working Xray proxy
        working_proxy_name: Human-readable name of the working proxy
    """
    loop = asyncio.get_running_loop()
    start_time = loop.time()
    log.info(
        f"Cross-test: checking {target_host}:{target_port} via {working_proxy_name} ({working_proxy_share.protocol})"
    )

    xray = XrayInstance(working_proxy_share)

    try:
        socks_port = await xray.start()
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

    socks_url = f"socks5://{xray.socks_user}:{xray.socks_password}@127.0.0.1:{socks_port}"

    # Use http:// to test raw TCP connectivity to the target through the Xray tunnel.
    # Xray routing is configured to route all traffic through the proxy outbound,
    # so this tests whether target_host:target_port is reachable from the proxy's location.
    test_url = f"http://{target_host}:{target_port}/"

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                test_url,
                proxy=socks_url,
                timeout=aiohttp.ClientTimeout(total=15, connect=10),
                allow_redirects=False,
            ) as response,
        ):
            duration_ms = (loop.time() - start_time) * 1000
            return DiagnosticResult(
                check_name="Xray Cross-Proxy Connectivity",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=(
                    f"✓ Сервер доступен через {working_proxy_name}: "
                    f"{target_host}:{target_port} → HTTP {response.status}, {round(duration_ms)}ms"
                ),
                details={
                    "target_host": target_host,
                    "target_port": target_port,
                    "target_protocol": target_protocol,
                    "working_proxy": working_proxy_name,
                    "working_proxy_protocol": working_proxy_share.protocol,
                    "http_status": response.status,
                    "duration_ms": round(duration_ms, 2),
                },
                recommendations=[
                    "Сервер доступен через другой рабочий прокси",
                    "Возможно, сервер заблокирован (RKN) или недоступен из вашего местоположения",
                    "Попробуйте использовать другой сервер из подписки",
                ],
            )

    except aiohttp.ServerDisconnectedError:
        # Target is not HTTP but TCP connection succeeded — server is reachable
        duration_ms = (loop.time() - start_time) * 1000
        return DiagnosticResult(
            check_name="Xray Cross-Proxy Connectivity",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=(
                f"✓ Сервер доступен через {working_proxy_name}: "
                f"{target_host}:{target_port} — TCP подключение установлено, {round(duration_ms)}ms"
            ),
            details={
                "target_host": target_host,
                "target_port": target_port,
                "target_protocol": target_protocol,
                "working_proxy": working_proxy_name,
                "working_proxy_protocol": working_proxy_share.protocol,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Сервер доступен через другой рабочий прокси",
                "Возможно, сервер заблокирован (RKN) или недоступен из вашего местоположения",
                "Попробуйте использовать другой сервер из подписки",
            ],
        )

    except TimeoutError:
        duration_ms = (loop.time() - start_time) * 1000
        return DiagnosticResult(
            check_name="Xray Cross-Proxy Connectivity",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"Таймаут через {working_proxy_name}: {target_host}:{target_port}",
            details={
                "target_host": target_host,
                "target_port": target_port,
                "target_protocol": target_protocol,
                "working_proxy": working_proxy_name,
                "working_proxy_protocol": working_proxy_share.protocol,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Сервер недоступен даже через другой рабочий прокси",
                "Возможно, сервер выключен или заблокирован на уровне сети",
                "Проверьте статус сервера на других ресурсах",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (loop.time() - start_time) * 1000
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
        await xray.stop()
