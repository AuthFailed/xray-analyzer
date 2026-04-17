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

    .. deprecated::
        Prefer managing the Xray lifecycle externally (via ``launched_xray``)
        and calling :func:`check_proxy_connectivity`,
        :func:`check_proxy_exit_ip_xray`, :func:`check_proxy_sni_xray`
        directly for more control (e.g. running censorship canary checks
        through the same tunnel).
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
                        f"Domain {share.server} did not respond, but IP {fallback_server_ip} works "
                        f"(likely DNS / geo-blocking). Proxy is usable via IP."
                    ),
                    details={
                        "domain": share.server,
                        "fallback_ip": fallback_server_ip,
                        "http_status": ip_connectivity.details.get("http_status"),
                    },
                ),
            )

    return results


async def run_xray_checks(
    share: ProxyShareURL,
    socks_url: str,
    session: aiohttp.ClientSession,
    label_suffix: str = "",
) -> list[DiagnosticResult]:
    """Run connectivity, exit IP, and SNI checks through an already-running Xray tunnel.

    Unlike :func:`check_proxy_via_xray`, this function does NOT start or stop
    Xray — the caller owns the lifecycle. This allows the caller to run
    additional checks (censorship canary, Telegram, etc.) through the same
    tunnel before shutting it down.

    Returns a list of DiagnosticResults (connectivity is always first).
    """
    results: list[DiagnosticResult] = []

    # 1. Status check (gates the rest)
    status_result = await check_proxy_connectivity(session, socks_url, share, label_suffix=label_suffix)
    results.append(status_result)

    # 2+3. Exit IP + SNI in parallel (independent, both go through same tunnel).
    if status_result.status == CheckStatus.PASS:
        ip_result, sni_result = await asyncio.gather(
            check_proxy_exit_ip_xray(session, socks_url, share, label_suffix=label_suffix),
            check_proxy_sni_xray(session, socks_url, share, label_suffix=label_suffix),
        )
        results.append(ip_result)
        results.append(sni_result)

    return results


async def run_xray_checks_with_fallback(
    share: ProxyShareURL,
    socks_url: str,
    session: aiohttp.ClientSession,
    fallback_server_ip: str | None = None,
) -> list[DiagnosticResult]:
    """Run Xray checks with IP fallback logic through an already-running tunnel.

    This replicates the domain→IP fallback strategy from
    :func:`check_proxy_via_xray` but without managing the Xray lifecycle.

    When connectivity via domain fails and ``fallback_server_ip`` is provided,
    the function restarts Xray with the IP-based share and retests. Note that
    the IP fallback requires starting a *new* Xray instance (different config).
    """
    results: list[DiagnosticResult] = []

    # Run main test with domain
    main_results = await run_xray_checks(share, socks_url, session, label_suffix=f" (домен: {share.server})")
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

        # IP fallback needs a separate Xray instance (different server in config)
        xray = XrayInstance(ip_share)
        try:
            socks_port = await xray.start()
            ip_socks_url = f"socks5://{xray.socks_user}:{xray.socks_password}@127.0.0.1:{socks_port}"
            ip_results = await run_xray_checks(
                ip_share, ip_socks_url, session, label_suffix=f" (IP: {fallback_server_ip})"
            )
            results.extend(ip_results)

            ip_connectivity = next((r for r in ip_results if r.check_name.startswith("Proxy Xray Connectivity")), None)
            if ip_connectivity and ip_connectivity.status == CheckStatus.PASS:
                results = [r for r in results if r.status not in {CheckStatus.FAIL, CheckStatus.TIMEOUT}]
                results.insert(
                    0,
                    DiagnosticResult(
                        check_name="Proxy Xray Connectivity",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.WARNING,
                        message=(
                            f"Domain {share.server} did not respond, but IP {fallback_server_ip} works "
                            f"(likely DNS / geo-blocking). Proxy is usable via IP."
                        ),
                        details={
                            "domain": share.server,
                            "fallback_ip": fallback_server_ip,
                            "http_status": ip_connectivity.details.get("http_status"),
                        },
                    ),
                )
        except RuntimeError as e:
            log.error(f"Failed to start Xray for IP fallback {fallback_server_ip}: {e}")
        finally:
            await xray.stop()

    return results


# ---------------------------------------------------------------------------
# Public check functions — accept an external session + socks_url
# ---------------------------------------------------------------------------


async def check_proxy_connectivity(
    session: aiohttp.ClientSession,
    socks_url: str,
    share: ProxyShareURL,
    label_suffix: str = "",
) -> DiagnosticResult:
    """Check proxy connectivity through Xray SOCKS tunnel."""
    test_url = settings.proxy_status_check_url
    start_time = asyncio.get_running_loop().time()

    try:
        async with session.get(
            test_url,
            proxy=socks_url,
            timeout=aiohttp.ClientTimeout(total=15),
            allow_redirects=True,
        ) as response:
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
                    message=f"connected, HTTP {status_code}, {round(duration_ms)}ms",
                    details=details,
                )
            else:
                return DiagnosticResult(
                    check_name=f"Proxy Xray Connectivity{label_suffix}",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"HTTP {status_code}",
                    details=details,
                )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy Xray Connectivity{label_suffix}",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message="connection timeout",
            details={
                "protocol": share.protocol,
                "server": share.server,
                "test_url": test_url,
                "timeout_seconds": 15,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Xray could not connect through the proxy",
                "Check proxy settings (UUID, TLS, transport)",
                "The server may be blocked or unreachable",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy Xray Connectivity{label_suffix}",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"connection error — {e}",
            details={
                "protocol": share.protocol,
                "server": share.server,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Xray connection error",
                "Verify UUID, TLS, and transport settings",
                "Make sure the server is reachable",
            ],
        )


async def check_proxy_exit_ip_xray(
    session: aiohttp.ClientSession,
    socks_url: str,
    share: ProxyShareURL,
    label_suffix: str = "",
) -> DiagnosticResult:
    """Check exit IP through Xray SOCKS tunnel."""
    ip_check_url = settings.proxy_ip_check_url
    start_time = asyncio.get_running_loop().time()

    try:
        async with session.get(
            ip_check_url,
            proxy=socks_url,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as response:
            duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            if response.status != 200:
                return DiagnosticResult(
                    check_name=f"Proxy Exit IP (Xray){label_suffix}",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"HTTP {response.status}",
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
                message=f"Exit IP = {exit_ip}",
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
            message="Exit IP check timed out",
            details={"protocol": share.protocol, "timeout_seconds": 15, "duration_ms": round(duration_ms, 2)},
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy Exit IP (Xray){label_suffix}",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"{e}",
            details={"protocol": share.protocol, "error": str(e), "duration_ms": round(duration_ms, 2)},
        )


async def check_proxy_sni_xray(
    session: aiohttp.ClientSession,
    socks_url: str,
    share: ProxyShareURL,
    label_suffix: str = "",
) -> DiagnosticResult:
    """Check SNI connection through Xray SOCKS tunnel."""
    sni_domain = settings.proxy_sni_domain
    test_url = f"https://{sni_domain}"
    start_time = asyncio.get_running_loop().time()

    try:
        async with session.get(
            test_url,
            proxy=socks_url,
            timeout=aiohttp.ClientTimeout(total=15),
            allow_redirects=True,
        ) as response:
            duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
            status_code = response.status

            if status_code in (200, 204, 301, 302, 304):
                return DiagnosticResult(
                    check_name=f"Proxy SNI Connection (Xray){label_suffix}",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=f"connected to {sni_domain}, HTTP {status_code}",
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
                    message=f"{sni_domain} returned HTTP {status_code}",
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
            message=f"connection to {sni_domain} timed out",
            details={"protocol": share.protocol, "sni_domain": sni_domain, "duration_ms": round(duration_ms, 2)},
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name=f"Proxy SNI Connection (Xray){label_suffix}",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"error connecting to {sni_domain} — {e}",
            details={"protocol": share.protocol, "error": str(e), "duration_ms": round(duration_ms, 2)},
        )


# ---------------------------------------------------------------------------
# Private helpers (compat for check_proxy_via_xray)
# ---------------------------------------------------------------------------


async def _run_xray_tests(
    share: ProxyShareURL,
    label_suffix: str = "",
) -> list[DiagnosticResult]:
    """Run the full suite of Xray tests (connectivity, exit IP, SNI).

    .. deprecated::
        Used only by :func:`check_proxy_via_xray`. New code should use
        :func:`run_xray_checks` with an externally-managed Xray instance.
    """
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
                message=f"Failed to start Xray: {e}",
                details={
                    "protocol": share.protocol,
                    "server": share.server,
                    "port": share.port,
                    "error": str(e),
                },
                recommendations=[
                    "Install Xray core: https://github.com/XTLS/Xray-core",
                    "Set XRAY_BINARY_PATH to the binary location",
                    "Verify the binary is on PATH: which xray",
                ],
            )
        )
        return results

    socks_url = f"socks5://{xray.socks_user}:{xray.socks_password}@127.0.0.1:{socks_port}"

    try:
        async with aiohttp.ClientSession() as session:
            return await run_xray_checks(share, socks_url, session, label_suffix=label_suffix)
    finally:
        if xray_started:
            await xray.stop()
