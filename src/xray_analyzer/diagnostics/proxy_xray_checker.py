"""Proxy testing through Xray core for VLESS/Trojan/Shadowsocks protocols."""

import asyncio
from dataclasses import replace
from typing import Any

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL
from xray_analyzer.diagnostics.xray_manager import XrayInstance

log = get_logger("proxy_xray_checker")

# Protocols that require Xray core
XRAY_PROTOCOLS = {"vless", "trojan", "ss", "shadowsocks"}


async def check_proxy_via_xray(
    share: ProxyShareURL,
    fallback_server_ip: str | None = None,
) -> list[DiagnosticResult]:
    """
    Test a VLESS/Trojan/SS proxy by launching Xray core.

    Returns multiple diagnostic results:
    1. Proxy connectivity (status check via PROXY_STATUS_CHECK_URL)
    2. Exit IP check (via PROXY_IP_CHECK_URL)
    3. SNI connection test (via proxy_sni_domain)

    If the main connectivity test fails and `fallback_server_ip` is provided,
    an additional test is performed using the IP instead of the domain name.

    The Xray subprocess is started and stopped for each test.
    """
    results: list[DiagnosticResult] = []

    if not settings.xray_test_enabled:
        results.append(
            DiagnosticResult(
                check_name="Proxy Xray Test",
                status=CheckStatus.SKIP,
                severity=CheckSeverity.INFO,
                message="Xray testing is disabled in configuration",
                details={"protocol": share.protocol, "server": share.server},
            )
        )
        return results

    # Run main test with domain
    main_results = await _run_xray_tests(share, label_suffix=f" (домен: {share.server})")
    results.extend(main_results)

    # If main test failed and we have a fallback IP, test with IP
    connectivity_result = next((r for r in results if r.check_name.startswith("Proxy Xray Connectivity")), None)

    if (
        fallback_server_ip
        and connectivity_result
        and connectivity_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
    ):
        log.info(f"Main test failed for {share.server}, trying fallback with IP: {fallback_server_ip}")
        ip_share = replace(share, server=fallback_server_ip)
        ip_results = await _run_xray_tests(ip_share, label_suffix=f" (IP: {fallback_server_ip})")
        results.extend(ip_results)

        # If fallback IP tests succeeded, replace failed domain results
        ip_connectivity = next((r for r in ip_results if r.check_name.startswith("Proxy Xray Connectivity")), None)
        if ip_connectivity and ip_connectivity.status == CheckStatus.PASS:
            # Remove failed domain tests and keep only the successful IP fallback results
            results = [r for r in results if r.status not in {CheckStatus.FAIL, CheckStatus.TIMEOUT}]
            # Add a note that domain test failed but IP worked
            results.insert(
                0,
                DiagnosticResult(
                    check_name="Proxy Xray Connectivity",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.WARNING,
                    message=(
                        f"Домен {share.server} не отвечал, но IP {fallback_server_ip} работает "
                        f"(возможно DNS/geo-blocking). Прокси рабочий."
                    ),
                    details={
                        "domain": share.server,
                        "fallback_ip": fallback_server_ip,
                        "http_status": ip_connectivity.details.get("http_status"),
                    },
                ),
            )

    return results


async def _run_xray_tests(
    share: ProxyShareURL,
    label_suffix: str = "",
) -> list[DiagnosticResult]:
    """Run the full suite of Xray tests (connectivity, exit IP, SNI)."""
    results: list[DiagnosticResult] = []
    xray = XrayInstance(share)
    socks_port = 0
    xray_started = False

    try:
        socks_port = await xray.start()
        xray_started = True
    except RuntimeError as e:
        log.error(f"Failed to start Xray for {share.name}: {e}")
        results.append(
            DiagnosticResult(
                check_name=f"Proxy Xray Connectivity{label_suffix}",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                message=f"Не удалось запустить Xray: {e}",
                details={
                    "protocol": share.protocol,
                    "server": share.server,
                    "port": share.port,
                    "error": str(e),
                },
                recommendations=[
                    "Установите Xray core: https://github.com/XTLS/Xray-core",
                    "Укажите путь к бинарному файлу через XRAY_BINARY_PATH",
                    "Проверьте, что бинарный файл доступен: which xray",
                ],
            )
        )
        return results

    socks_url = f"socks5://{xray.socks_user}:{xray.socks_password}@127.0.0.1:{socks_port}"

    try:
        # 1. Status check
        status_result = await _check_proxy_status(socks_url, share, label_suffix=label_suffix)
        results.append(status_result)

        # 2. Exit IP check (only if status passed)
        if status_result.status == CheckStatus.PASS:
            ip_result = await _check_proxy_exit_ip(socks_url, share, label_suffix=label_suffix)
            results.append(ip_result)

            # 3. SNI connection check
            sni_result = await _check_proxy_sni(socks_url, share, label_suffix=label_suffix)
            results.append(sni_result)
        else:
            results.append(
                DiagnosticResult(
                    check_name=f"Proxy Exit IP (Xray){label_suffix}",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message="Пропущено — проверка подключения не прошла",
                    details={"protocol": share.protocol},
                )
            )
            results.append(
                DiagnosticResult(
                    check_name=f"Proxy SNI Connection (Xray){label_suffix}",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message="Пропущено — проверка подключения не прошла",
                    details={"protocol": share.protocol},
                )
            )

    finally:
        if xray_started:
            await xray.stop()

    return results


async def _check_proxy_status(
    socks_url: str,
    share: ProxyShareURL,
    label_suffix: str = "",
) -> DiagnosticResult:
    """Check proxy connectivity through Xray SOCKS tunnel."""
    test_url = settings.proxy_status_check_url
    start_time = asyncio.get_running_loop().time()

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                test_url,
                proxy=socks_url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as response,
        ):
            duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            status_code = response.status

            details: dict[str, Any] = {
                "protocol": share.protocol,
                "server": share.server,
                "port": share.port,
                "test_url": test_url,
                "http_status": status_code,
                "duration_ms": round(duration_ms, 2),
                "local_socks_port": share.port,
            }

            if status_code in (200, 204):
                return DiagnosticResult(
                    check_name=f"Proxy Xray Connectivity{label_suffix}",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=(
                        f"{share.name} ({share.protocol}): подключился, HTTP {status_code}, {round(duration_ms)}ms"
                    ),
                    details=details,
                )
            else:
                return DiagnosticResult(
                    check_name=f"Proxy Xray Connectivity{label_suffix}",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"{share.name} ({share.protocol}): HTTP {status_code}",
                    details=details,
                )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy Xray Connectivity{label_suffix}",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"{share.name} ({share.protocol}): таймаут подключения",
            details={
                "protocol": share.protocol,
                "server": share.server,
                "test_url": test_url,
                "timeout_seconds": 15,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Xray не смог подключиться через прокси",
                "Проверьте настройки прокси (UUID, TLS, transport)",
                "Возможно, сервер заблокирован или недоступен",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy Xray Connectivity{label_suffix}",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"{share.name} ({share.protocol}): ошибка подключения — {e}",
            details={
                "protocol": share.protocol,
                "server": share.server,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Ошибка подключения через Xray",
                "Проверьте UUID, настройки TLS и transport",
                "Убедитесь, что сервер доступен",
            ],
        )


async def _check_proxy_exit_ip(
    socks_url: str,
    share: ProxyShareURL,
    label_suffix: str = "",
) -> DiagnosticResult:
    """Check exit IP through Xray SOCKS tunnel."""
    ip_check_url = settings.proxy_ip_check_url
    start_time = asyncio.get_running_loop().time()

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                ip_check_url,
                proxy=socks_url,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response,
        ):
            duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            if response.status != 200:
                return DiagnosticResult(
                    check_name=f"Proxy Exit IP (Xray){label_suffix}",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"{share.name} ({share.protocol}): HTTP {response.status}",
                    details={
                        "protocol": share.protocol,
                        "http_status": response.status,
                        "duration_ms": round(duration_ms, 2),
                    },
                )

            exit_ip = (await response.text()).strip()
            return DiagnosticResult(
                check_name=f"Proxy Exit IP (Xray){label_suffix}",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"{share.name} ({share.protocol}): Exit IP = {exit_ip}",
                details={
                    "protocol": share.protocol,
                    "exit_ip": exit_ip,
                    "duration_ms": round(duration_ms, 2),
                },
            )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy Exit IP (Xray){label_suffix}",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"{share.name} ({share.protocol}): таймаут проверки Exit IP",
            details={"protocol": share.protocol, "timeout_seconds": 15, "duration_ms": round(duration_ms, 2)},
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy Exit IP (Xray){label_suffix}",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"{share.name} ({share.protocol}): {e}",
            details={"protocol": share.protocol, "error": str(e), "duration_ms": round(duration_ms, 2)},
        )


async def _check_proxy_sni(
    socks_url: str,
    share: ProxyShareURL,
    label_suffix: str = "",
) -> DiagnosticResult:
    """Check SNI connection through Xray SOCKS tunnel."""
    sni_domain = settings.proxy_sni_domain
    test_url = f"https://{sni_domain}"
    start_time = asyncio.get_running_loop().time()

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                test_url,
                proxy=socks_url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as response,
        ):
            duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            status_code = response.status

            if status_code in (200, 204, 301, 302, 304):
                return DiagnosticResult(
                    check_name=f"Proxy SNI Connection (Xray){label_suffix}",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=f"{share.name} ({share.protocol}): подключился к {sni_domain}, HTTP {status_code}",
                    details={
                        "protocol": share.protocol,
                        "sni_domain": sni_domain,
                        "http_status": status_code,
                        "duration_ms": round(duration_ms, 2),
                    },
                )
            else:
                return DiagnosticResult(
                    check_name=f"Proxy SNI Connection (Xray){label_suffix}",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.WARNING,
                    message=f"{share.name} ({share.protocol}): {sni_domain} вернул HTTP {status_code}",
                    details={
                        "protocol": share.protocol,
                        "sni_domain": sni_domain,
                        "http_status": status_code,
                        "duration_ms": round(duration_ms, 2),
                    },
                )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy SNI Connection (Xray){label_suffix}",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"{share.name} ({share.protocol}): таймаут подключения к {sni_domain}",
            details={"protocol": share.protocol, "sni_domain": sni_domain, "duration_ms": round(duration_ms, 2)},
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy SNI Connection (Xray){label_suffix}",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"{share.name} ({share.protocol}): ошибка подключения к {sni_domain} — {e}",
            details={"protocol": share.protocol, "error": str(e), "duration_ms": round(duration_ms, 2)},
        )
