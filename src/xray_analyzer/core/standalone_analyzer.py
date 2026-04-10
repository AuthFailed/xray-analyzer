"""Standalone analyzer for testing proxies from subscription without checker API."""

import asyncio
import re
from ipaddress import ip_address

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import (
    CheckSeverity,
    CheckStatus,
    DiagnosticResult,
    HostDiagnostic,
)
from xray_analyzer.diagnostics.dns_checker import check_dns_with_checkhost
from xray_analyzer.diagnostics.proxy_ip_checker import check_proxy_exit_ip
from xray_analyzer.diagnostics.proxy_sni_checker import check_proxy_sni_connection
from xray_analyzer.diagnostics.proxy_tcp_checker import check_proxy_tcp_tunnel
from xray_analyzer.diagnostics.proxy_xray_checker import (
    XRAY_PROTOCOLS,
    check_proxy_via_xray,
)
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL
from xray_analyzer.diagnostics.tcp_checker import check_tcp_connection
from xray_analyzer.diagnostics.tcp_ping_checker import check_tcp_ping
from xray_analyzer.diagnostics.xray_manager import XrayInstance

log = get_logger("standalone_analyzer")


def _is_valid_server_address(server: str) -> bool:
    """
    Check if a server string looks like a valid domain or IP address.

    Returns False for:
    - Virtual placeholders: virt.host, localhost, 127.0.0.1
    - Invalid IPs: 0.0.0.0, 0.0.0.1, 1, etc.
    - Non-domain strings: numbers, single letters, etc.
    """
    if not server:
        return False

    # Virtual host placeholders
    virtual_hosts = {"virt.host", "localhost", "127.0.0.1"}
    if server in virtual_hosts:
        return False

    # Check if it looks like an IP address
    try:
        ip = ip_address(server)
        return not (ip.is_unspecified or ip.is_loopback or ip.is_reserved)
    except ValueError:
        pass

    # Check if it looks like a valid domain
    # Must have at least one dot and valid characters
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    return bool(domain_pattern.match(server))


async def analyze_subscription_proxies(
    shares: list[ProxyShareURL],
) -> list[HostDiagnostic]:
    """
    Run full diagnostic analysis on all proxies from subscription.

    This is a standalone mode that doesn't require checker API.
    For each proxy, it runs:
    - DNS resolution
    - TCP connection & ping
    - For HTTP/SOCKS: tunnel test, exit IP, SNI
    - For VLESS/Trojan/SS: Xray connectivity, exit IP, SNI
    - Cross-proxy tests for problematic hosts

    Args:
        shares: List of proxy share URLs from subscription

    Returns:
        List of HostDiagnostic for each proxy
    """
    log.info(f"Starting standalone analysis of {len(shares)} proxies")

    # Run diagnostics concurrently on all proxies
    tasks = [analyze_single_proxy(share) for share in shares]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    diagnostics: list[HostDiagnostic] = []
    for result in results:
        if isinstance(result, Exception):
            log.error(f"Error during analysis: {result}", exc_info=result)
        elif isinstance(result, HostDiagnostic):
            diagnostics.append(result)

    # Run cross-proxy tests for problematic hosts
    problematic = [d for d in diagnostics if d.overall_status != CheckStatus.PASS]
    if problematic:
        await _run_standalone_cross_tests(problematic, shares, diagnostics)

    log.info(f"Standalone analysis complete: {len(diagnostics)} proxies analyzed")
    return diagnostics


async def analyze_single_proxy(share: ProxyShareURL) -> HostDiagnostic:
    """Run all diagnostic checks on a single proxy."""
    host = share.server
    port = share.port

    # Build display label: use proxy name for readability
    label = f"{share.name} ({host}:{port})"

    # Skip virtual host placeholders
    if host in {"virt.host", "localhost", "127.0.0.1"}:
        log.debug(f"Skipping virtual host '{host}' for proxy {share.name}")
        return HostDiagnostic(host=label)

    # Skip invalid server addresses
    if not _is_valid_server_address(host):
        log.debug(f"Skipping invalid server address '{host}' for proxy {share.name}")
        return HostDiagnostic(host=label)

    log.info(f"Analyzing proxy: {share.name} → {host}:{port}")

    diagnostic = HostDiagnostic(host=label)

    # 1. DNS Resolution
    dns_result = await check_dns_with_checkhost(host)
    diagnostic.add_result(dns_result)

    # 2. TCP Connection
    tcp_result = await check_tcp_connection(host, port)
    diagnostic.add_result(tcp_result)

    # 3. TCP Ping
    tcp_ping_result = await check_tcp_ping(host, port)
    diagnostic.add_result(tcp_ping_result)

    # 4. Protocol-specific tests
    if share.protocol.lower() in XRAY_PROTOCOLS:
        # VLESS/Trojan/SS - test via Xray
        if not settings.xray_test_enabled:
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="Proxy Xray Test",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message=f"Xray testing disabled (--no-xray). Для тестирования {share.protocol} требуется Xray core",
                    details={"protocol": share.protocol, "server": share.server, "port": share.port},
                )
            )
        else:
            fallback_ip = None
            if dns_result.status == CheckStatus.PASS:
                local_ips = dns_result.details.get("local_ips", [])
                fallback_ip = local_ips[0] if local_ips else None

            xray_results = await check_proxy_via_xray(share, fallback_server_ip=fallback_ip)
            for result in xray_results:
                diagnostic.add_result(result)
    else:
        # HTTP/SOCKS - test directly
        proxy_url = f"{share.protocol}://{host}:{port}"

        # Proxy TCP Tunnel
        tunnel_result = await check_proxy_tcp_tunnel(proxy_url)
        diagnostic.add_result(tunnel_result)

        # Exit IP
        exit_ip_result = await check_proxy_exit_ip(proxy_url)
        diagnostic.add_result(exit_ip_result)

        # SNI check (if enabled)
        if settings.proxy_sni_test_enabled:
            sni_result = await check_proxy_sni_connection(proxy_url)
            diagnostic.add_result(sni_result)

    # Add smart recommendations based on test results
    _add_standalone_recommendations(diagnostic, share)

    return diagnostic


def _add_standalone_recommendations(diagnostic: HostDiagnostic, share: ProxyShareURL) -> None:
    """Add actionable recommendations based on diagnostic results."""
    results = diagnostic.results

    # Extract server info
    server_domain = share.server
    server_ip = None
    for r in results:
        if r.check_name.startswith("DNS Resolution") and r.status == CheckStatus.PASS:
            local_ips = r.details.get("local_ips", [])
            if local_ips:
                server_ip = local_ips[0]
                break

    # DNS mismatch with Check-Host (geo-blocking indicator)
    dns_warning = next(
        (r for r in results if r.check_name.startswith("DNS Resolution") and r.severity == CheckSeverity.WARNING),
        None,
    )
    if dns_warning:
        diagnostic.add_recommendation(
            f"⚠️ DNS для {server_domain} не совпадает с Check-Host (geo-blocking)"
        )
        diagnostic.add_recommendation(
            "Локальный DNS возвращает другие IP, чем внешние ноды Check-Host.net"
        )

    # Check if Xray connectivity passed but Exit IP/SNI failed
    xray_connectivity_passed = any(
        r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS
        for r in results
    )
    exit_ip_failed = any(
        r.check_name.startswith("Proxy Exit IP") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        for r in results
    )
    sni_failed = any(
        r.check_name.startswith("Proxy SNI") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        for r in results
    )

    if xray_connectivity_passed and (exit_ip_failed or sni_failed):
        failed_services = []
        if exit_ip_failed:
            failed_services.append("Exit IP check")
        if sni_failed:
            failed_services.append("SNI check")
        diagnostic.add_recommendation(
            f"⚠️ Сервер {server_domain} подключается, но не достигает внешних сервисов"
        )
        diagnostic.add_recommendation(
            f"Причина: Xray подключился (HTTP 204), но {', '.join(failed_services)} провалились — "
            f"сервер не может достичь внешних хостов"
        )
        diagnostic.add_recommendation(
            "Решения:\n"
            "  1) Проверить маршрутизацию и firewall на сервере\n"
            "  2) Убедиться что сервер имеет доступ к внешнему интернету\n"
            "  3) Проверить DNS-настройки сервера (resolv.conf)"
        )

    # Xray connectivity failed but IP fallback worked
    xray_domain_failed = any(
        r.check_name.startswith("Proxy Xray Connectivity")
        and "домен:" in r.check_name
        and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        for r in results
    )
    xray_ip_passed = any(
        r.check_name.startswith("Proxy Xray Connectivity")
        and "IP:" in r.check_name
        and r.status == CheckStatus.PASS
        for r in results
    )

    if xray_domain_failed and xray_ip_passed:
        ip_str = server_ip or "IP"
        diagnostic.add_recommendation(f"🔒 Домен {server_domain} заблокирован (DNS/SNI)")
        diagnostic.add_recommendation(
            f"Причина: по домену не подключается, но по IP ({ip_str}) проходит"
        )
        diagnostic.add_recommendation(
            "Решения:\n"
            "  1) Заменить домен на новый в конфигурации сервера\n"
            "  2) Настроить клиентов на подключение по IP вместо домена\n"
            "  3) Использовать SNI-обфускацию или selfsteal-сертификат"
        )

    # Xray connectivity failed (both domain and IP)
    xray_domain_failed = any(
        r.check_name.startswith("Proxy Xray Connectivity")
        and "домен:" in r.check_name
        and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        for r in results
    )
    xray_ip_failed = any(
        r.check_name.startswith("Proxy Xray Connectivity")
        and "IP:" in r.check_name
        and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        for r in results
    )

    if xray_domain_failed and xray_ip_failed:
        ip_str = f"IP {server_ip}" if server_ip else server_domain
        diagnostic.add_recommendation(f"🚫 {ip_str} не отвечает — таймаут подключения")
        diagnostic.add_recommendation(
            "Причина: сервер не отвечает ни по домену, ни по IP — возможно выключен или заблокирован"
        )
        diagnostic.add_recommendation(
            "Решения:\n"
            "  1) Проверить доступность сервера и перезапустить\n"
            "  2) Проверить Xray-конфиг (UUID, порты, сертификаты)"
        )


# --- Cross-proxy tests ---


async def _run_standalone_cross_tests(
    problematic: list[HostDiagnostic],
    shares: list[ProxyShareURL],
    all_diagnostics: list[HostDiagnostic],
) -> None:
    """
    Run cross-proxy tests in standalone mode.

    Find a working proxy and use it to test connectivity to problematic hosts.
    This helps determine if the issue is with the server or our local network.
    """
    # Find a working proxy from passing diagnostics
    passing = [d for d in all_diagnostics if d.overall_status == CheckStatus.PASS]

    # Extract working share URL from a passing diagnostic
    working_share: ProxyShareURL | None = None
    for diag in passing:
        # Extract server:port from diagnostic host label
        host = diag.host
        start = host.rfind("(")
        end = host.rfind(")")
        if start == -1 or end == -1:
            continue
        diag_server_port = host[start + 1 : end]

        # Find matching share
        for share in shares:
            if f"{share.server}:{share.port}" == diag_server_port:
                working_share = share
                break
        if working_share:
            break

    if not working_share:
        log.info("No working proxy found for cross-tests")
        return

    log.info(f"Using {working_share.name} ({working_share.server}:{working_share.port}) for cross-tests")

    # Launch Xray for the working proxy
    xray = XrayInstance(working_share)
    socks_port = 0
    xray_started = False

    try:
        socks_port = await xray.start()
        xray_started = True
        socks_url = f"socks5://127.0.0.1:{socks_port}"

        test_url = settings.proxy_status_check_url

        # Test each problematic host through the working proxy
        for diag in problematic:
            # Extract server:port from diagnostic
            host = diag.host
            start = host.rfind("(")
            end = host.rfind(")")
            if start == -1 or end == -1:
                continue
            server_port = host[start + 1 : end]
            parts = server_port.rsplit(":", 1)
            if len(parts) != 2:
                continue
            target_host, target_port_str = parts
            try:
                target_port = int(target_port_str)
            except ValueError:
                continue

            # Skip if target is the same as working proxy
            if target_host == working_share.server and target_port == working_share.port:
                continue

            # Skip if target server is same as working proxy server (different port)
            if target_host == working_share.server:
                continue

            log.info(f"Cross-test: checking {target_host}:{target_port} via {working_share.name}")

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
                    status_code = response.status
                    if status_code in (200, 204):
                        diag.add_recommendation(
                            f"✓ {target_host}:{target_port} доступен через {working_share.name} (HTTP {status_code})"
                        )
                        diag.add_recommendation(
                            "Причина: сервер работает через другой прокси — "
                            "возможно заблокирован для прямых подключений из нашей сети"
                        )
                        diag.add_recommendation(
                            "Решения:\n"
                            "  1) Использовать мост (bridge) через рабочий прокси\n"
                            "  2) Сменить IP-адрес сервера на новый из другой подсети\n"
                            "  3) Настроить клиентов на подключение через рабочий прокси"
                        )
                    else:
                        diag.add_recommendation(
                            f"⚠ {target_host}:{target_port} → HTTP {status_code} через {working_share.name}"
                        )
            except TimeoutError:
                diag.add_recommendation(
                    f"✗ {target_host}:{target_port} недоступен через {working_share.name}: таймаут"
                )
                diag.add_recommendation(
                    "Сервер не отвечает даже через рабочий прокси — "
                    "возможно сервер выключен или заблокирован глобально"
                )
            except aiohttp.ClientError as e:
                diag.add_recommendation(
                    f"✗ {target_host}:{target_port} недоступен через {working_share.name}: {e}"
                )
    except Exception as e:
        log.error(f"Failed to start working proxy for cross-tests: {e}")
    finally:
        if xray_started:
            await xray.stop()
