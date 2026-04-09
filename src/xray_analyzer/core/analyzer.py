"""Main analyzer that orchestrates all diagnostic checks."""

import asyncio
from typing import Any

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import (
    CheckSeverity,
    CheckStatus,
    DiagnosticResult,
    HostDiagnostic,
    ProxyInfo,
    ProxyStatus,
)
from xray_analyzer.core.xray_client import XrayCheckerClient
from xray_analyzer.diagnostics.dns_checker import check_dns_with_checkhost
from xray_analyzer.diagnostics.proxy_cross_checker import (
    check_via_proxy,
    check_xray_cross_connectivity,
)
from xray_analyzer.diagnostics.proxy_ip_checker import check_proxy_exit_ip
from xray_analyzer.diagnostics.proxy_sni_checker import check_proxy_sni_connection
from xray_analyzer.diagnostics.proxy_tcp_checker import check_proxy_tcp_tunnel
from xray_analyzer.diagnostics.proxy_xray_checker import (
    XRAY_PROTOCOLS,
    check_proxy_via_xray,
)
from xray_analyzer.diagnostics.rkn_checker import check_rkn_blocking, extract_domain_from_url
from xray_analyzer.diagnostics.subscription_parser import (
    ProxyShareURL,
    fetch_subscription,
    find_share_url_for_proxy,
)
from xray_analyzer.diagnostics.tcp_checker import check_tcp_connection
from xray_analyzer.diagnostics.tcp_ping_checker import check_tcp_ping
from xray_analyzer.diagnostics.tunnel_checker import check_proxy_tunnel
from xray_analyzer.diagnostics.xray_downloader import ensure_xray
from xray_analyzer.notifiers.manager import NotifierManager

log = get_logger("analyzer")


class XrayAnalyzer:
    """Main analyzer that orchestrates all diagnostic checks."""

    def __init__(self) -> None:
        self.client = XrayCheckerClient()
        self.notifier_manager = NotifierManager()
        self._subscription_shares: list[ProxyShareURL] = []

    async def run_full_analysis(self) -> list[HostDiagnostic]:
        """
        Run complete diagnostic analysis on all proxies.

        By default, only analyzes offline proxies. Set ANALYZE_ONLINE_PROXIES=true
        in .env to analyze all proxies.

        Returns list of HostDiagnostic objects for each problematic host.
        """
        log.info("Starting full analysis")

        # Load subscription share URLs (for VLESS/Trojan/SS testing)
        if settings.subscription_url and settings.xray_test_enabled:
            try:
                self._subscription_shares = await fetch_subscription(
                    settings.subscription_url,
                    hwid=settings.subscription_hwid,
                )
                log.info(f"Loaded {len(self._subscription_shares)} proxies from subscription")
                # Log loaded shares for debugging
                for s in self._subscription_shares:
                    log.info(f"  Share: {s.name} | {s.server}:{s.port} | {s.protocol}")
            except Exception as e:
                log.warning(f"Failed to load subscription: {e}")

        # Ensure Xray binary is available if testing VLESS/Trojan/SS
        if settings.xray_test_enabled:
            xray_path = await ensure_xray(settings.xray_binary_path)
            if xray_path:
                settings.xray_binary_path = xray_path
                log.info(f"Xray available at: {xray_path}")
            else:
                log.warning(
                    "Xray binary not found and auto-download failed. "
                    "VLESS/Trojan/SS proxy tests will be skipped. "
                    "Set XRAY_BINARY_PATH or install xray manually."
                )

        # Get all proxies from checker API
        proxies = await self._get_proxies()
        if not proxies:
            log.warning("No proxies found from checker API")
            return []

        # Filter to only offline proxies by default
        offline_only = not getattr(settings, "analyze_online_proxies", False)
        if offline_only:
            targets = [p for p in proxies if not p.online]  # type: ignore
            log.info(f"Found {len(targets)} offline proxies out of {len(proxies)} total")
        else:
            targets = proxies
            log.info(f"Found {len(proxies)} proxies to analyze")

        if not targets:
            log.info("No proxies to analyze — all are online")
            return []

        # Run diagnostics on each proxy
        diagnostics: list[HostDiagnostic] = []
        tasks = []

        for proxy in targets:
            tasks.append(self._analyze_proxy(proxy))

        # Run all analyses concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                log.error(f"Error during analysis: {result}", exc_info=result)
            elif isinstance(result, HostDiagnostic):
                diagnostics.append(result)

        # Filter to only problematic hosts
        problematic = [d for d in diagnostics if d.overall_status != CheckStatus.PASS]

        # Run cross-proxy tests for problematic hosts
        if problematic and proxies:
            # 1. HTTP/SOCKS cross-test
            working_proxy = self._find_working_http_socks_proxy(proxies)
            if working_proxy:
                log.info(f"Found working proxy for cross-test: {working_proxy.server}:{working_proxy.port}")
                await self._run_cross_proxy_tests(problematic, working_proxy)
            else:
                log.info("No working HTTP/SOCKS proxy found for cross-test")

            # 2. Xray cross-test (for VLESS/Trojan/SS proxies that failed)
            if self._subscription_shares:
                working_xray_proxy = self._find_working_xray_proxy(proxies)
                if working_xray_proxy:
                    log.info(f"Found working Xray proxy for cross-test: {working_xray_proxy.name}")
                    await self._run_xray_cross_proxy_tests(problematic, working_xray_proxy)
                else:
                    log.info("No working Xray proxy found for cross-test")

        log.info(f"Analysis complete: {len(problematic)} problematic out of {len(diagnostics)} total")

        # Send notifications if there are problems
        if problematic:
            await self.notifier_manager.notify(diagnostics)

        return diagnostics

    async def run_single_host_analysis(self, host: str, port: int = 443) -> HostDiagnostic:
        """Run diagnostic analysis on a single host."""
        log.info(f"Starting analysis for {host}:{port}")
        diagnostic = HostDiagnostic(host=f"{host}:{port}")

        # Run all checks
        await self._run_all_checks(diagnostic, host, port, None)

        return diagnostic

    async def _get_proxies(self) -> list[ProxyInfo | ProxyStatus]:
        """Get proxies from the checker API with retry on connection failure."""
        max_retries = 5
        retry_delay = 5

        for attempt in range(1, max_retries + 1):
            try:
                # Always try full proxy list first (has server/port info)
                try:
                    response = await self.client.get_all_proxies()
                    proxies = response.data
                    log.info(f"Got {len(proxies)} proxies from full endpoint")
                    return proxies  # type: ignore
                except Exception as e:
                    log.debug(f"Full endpoint unavailable: {e}")

                # Fall back to public endpoint (no server info — limited diagnostics)
                if not settings.is_api_protected:
                    log.warning(
                        "Using public API endpoint — server addresses not available. "
                        "Set CHECKER_API_USERNAME and CHECKER_API_PASSWORD for full diagnostics."
                    )

                response = await self.client.get_public_proxies()
                return response.data  # type: ignore

            except Exception as e:
                if attempt < max_retries:
                    log.warning(
                        f"Checker API unavailable (attempt {attempt}/{max_retries}), retrying in {retry_delay}s: {e}"
                    )
                    await asyncio.sleep(retry_delay)
                else:
                    log.error(f"Failed to get proxies after {max_retries} attempts: {e}")
                    return []

        return []

    async def _analyze_proxy(self, proxy: ProxyInfo | ProxyStatus) -> HostDiagnostic:
        """Run all diagnostic checks on a single proxy."""
        # Get real server address from full proxy info
        if hasattr(proxy, "server"):
            host = proxy.server  # type: ignore
            port = proxy.port  # type: ignore
        else:
            # Public endpoint — no server info available
            host = ""
            port = 0

        # Skip if no server info available
        if not host:
            log.warning(
                f"Skipping proxy {proxy.stable_id} — no server address "
                f"(public API endpoint, set auth credentials for full diagnostics)"
            )
            diagnostic = HostDiagnostic(host=f"{proxy.stable_id}:skipped")
            diagnostic.add_recommendation(
                "Настройте авторизацию (CHECKER_API_USERNAME/PASSWORD) для получения адресов серверов"
            )
            return diagnostic

        # Skip virtual host placeholders entirely
        virtual_hosts = {"virt.host", "localhost", "127.0.0.1"}
        if host in virtual_hosts:
            log.debug(f"Skipping virtual host '{host}' for proxy {proxy.stable_id} ({proxy.name})")
            return HostDiagnostic(host=f"{host}:{port}")

        log.info(f"Analyzing proxy: {proxy.name} → {host}:{port}")

        diagnostic = HostDiagnostic(host=f"{host}:{port}")

        await self._run_all_checks(diagnostic, host, port, proxy)

        return diagnostic

    async def _run_all_checks(
        self,
        diagnostic: HostDiagnostic,
        host: str,
        port: int,
        proxy: Any,
    ) -> None:
        """Run all diagnostic checks and add results to diagnostic."""

        # 1. DNS Resolution with Check-Host.net comparison
        dns_result = await check_dns_with_checkhost(host)
        diagnostic.add_result(dns_result)

        # If DNS fails, still run other checks to gather more diagnostics
        if dns_result.status == CheckStatus.FAIL:
            diagnostic.add_recommendation("DNS не разрешается — проверьте домен и DNS-настройки")

        # 2. TCP Connection
        tcp_result = await check_tcp_connection(host, port)
        diagnostic.add_result(tcp_result)

        # 3. TCP Ping check
        tcp_ping_result = await check_tcp_ping(host, port)
        diagnostic.add_result(tcp_ping_result)

        # 4. RKN Block Check (extract domain from host)
        domain = extract_domain_from_url(host) if "://" in host else host
        rkn_result = await check_rkn_blocking(domain)
        diagnostic.add_result(rkn_result)

        # Also check resolved IPs for RKN blocking
        if dns_result.status == CheckStatus.PASS:
            resolved_ips = dns_result.details.get("resolved_ips", [])
            for ip_addr in resolved_ips[:2]:  # Check first 2 IPs
                ip_rkn_result = await check_rkn_blocking(ip_addr)
                diagnostic.add_result(ip_rkn_result)

        # Proxy-specific checks (only if proxy is available)
        if proxy:
            protocol = getattr(proxy, "protocol", "http").lower()

            if protocol in XRAY_PROTOCOLS and self._subscription_shares:
                # VLESS/Trojan/SS — use Xray core for testing
                proxy_name = getattr(proxy, "name", "")
                share = find_share_url_for_proxy(self._subscription_shares, host, port, protocol, name=proxy_name)
                if share:
                    # Get resolved IP from DNS results for fallback testing.
                    # check_dns_with_checkhost stores IPs in "local_ips" key.
                    local_ips: list[str] = []
                    if dns_result.status == CheckStatus.PASS:
                        local_ips = dns_result.details.get("local_ips", [])
                    fallback_ip = local_ips[0] if local_ips else None

                    xray_results = await check_proxy_via_xray(share, fallback_server_ip=fallback_ip)
                    for result in xray_results:
                        diagnostic.add_result(result)
                else:
                    diagnostic.add_result(
                        DiagnosticResult(
                            check_name="Proxy Xray Test",
                            status=CheckStatus.SKIP,
                            severity=CheckSeverity.WARNING,
                            message=f"Не найден share URL для {host}:{port} ({protocol}) в подписке",
                            details={"protocol": protocol, "server": host, "port": port},
                            recommendations=[
                                "Проверьте, что subscription URL содержит данный прокси",
                                "Убедитесь, что SUBSCRIPTION_URL настроен корректно",
                            ],
                        )
                    )
            elif protocol in XRAY_PROTOCOLS:
                # Xray protocols but no subscription available
                diagnostic.add_result(
                    DiagnosticResult(
                        check_name="Proxy Xray Test",
                        status=CheckStatus.SKIP,
                        severity=CheckSeverity.INFO,
                        message=f"Для {protocol} требуется SUBSCRIPTION_URL в конфигурации",
                        details={"protocol": protocol, "server": host},
                        recommendations=[
                            "Укажите SUBSCRIPTION_URL для тестирования VLESS/Trojan/SS прокси",
                            "Или используйте xray-checker API для проверки статуса прокси",
                        ],
                    )
                )
            else:
                # HTTP/SOCKS — use existing aiohttp-based checks
                proxy_url = self._build_proxy_url(proxy)
                if proxy_url:
                    # 5. Proxy TCP Tunnel check
                    tunnel_result = await check_proxy_tcp_tunnel(proxy_url)
                    diagnostic.add_result(tunnel_result)

                    # 6. Proxy Exit IP check
                    exit_ip_result = await check_proxy_exit_ip(proxy_url)
                    diagnostic.add_result(exit_ip_result)

                    # 7. Proxy SNI check
                    if settings.proxy_sni_test_enabled:
                        sni_result = await check_proxy_sni_connection(proxy_url)
                        diagnostic.add_result(sni_result)

                    # 8. Legacy tunnel check (backward compatibility)
                    if settings.tunnel_test_enabled:
                        legacy_tunnel_result = await check_proxy_tunnel(proxy_url)
                        diagnostic.add_result(legacy_tunnel_result)

    def _build_proxy_url(self, proxy: Any) -> str | None:
        """Build a proxy URL from proxy info."""
        if hasattr(proxy, "server") and hasattr(proxy, "port"):
            protocol = getattr(proxy, "protocol", "http").lower()
            return f"{protocol}://{proxy.server}:{proxy.port}"
        return None

    def _find_working_http_socks_proxy(self, proxies: list[ProxyInfo | ProxyStatus]) -> ProxyInfo | ProxyStatus | None:
        """Find an online HTTP or SOCKS proxy for cross-testing."""
        for proxy in proxies:
            protocol = getattr(proxy, "protocol", "").lower()
            if (
                getattr(proxy, "online", False)
                and protocol in ("http", "socks", "socks5", "socks4")
                and hasattr(proxy, "server")
                and hasattr(proxy, "port")
            ):
                return proxy
        return None

    async def _run_cross_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """
        Test connectivity to problematic hosts through a working proxy.

        This helps determine if the issue is with the target server or
        with the local network/infrastructure.
        """
        working_proxy_url = self._build_proxy_url(working_proxy)
        if not working_proxy_url:
            return

        working_name = getattr(working_proxy, "name", f"{working_proxy.server}:{working_proxy.port}")  # type: ignore

        tasks = []
        for diag in problematic:
            # Parse host:port from diagnostic
            host_part = diag.host.rsplit(":", 1)
            if len(host_part) != 2:
                continue
            target_host = host_part[0]
            try:
                target_port = int(host_part[1])
            except ValueError:
                continue

            # Skip virtual hosts
            if target_host in ("virt.host", "localhost", "127.0.0.1"):
                continue

            tasks.append(self._cross_test_for_host(diag, target_host, target_port, working_proxy_url, working_name))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _cross_test_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        target_port: int,
        working_proxy_url: str,
        working_name: str,
    ) -> None:
        """Run a single cross-proxy test and add result to diagnostic."""
        try:
            result = await check_via_proxy(
                target_host,
                target_port,
                working_proxy_url,
                proxy_name=working_name,
            )
            diag.add_result(result)
            log.info(f"Cross-test {target_host}:{target_port} via {working_name}: {result.status.value}")
        except Exception as e:
            log.error(f"Cross-test failed for {target_host}:{target_port}: {e}")

    def _find_working_xray_proxy(self, proxies: list[ProxyInfo | ProxyStatus]) -> ProxyInfo | ProxyStatus | None:
        """Find an online VLESS/Trojan/SS proxy for Xray cross-testing."""
        for proxy in proxies:
            protocol = getattr(proxy, "protocol", "").lower()
            if (
                getattr(proxy, "online", False)
                and protocol in XRAY_PROTOCOLS
                and hasattr(proxy, "server")
                and hasattr(proxy, "port")
            ):
                return proxy
        return None

    async def _run_xray_cross_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_xray_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """
        Test connectivity to problematic Xray proxies through a working Xray proxy.

        This determines if the server is blocked from our location or if it's
        down entirely. We use a known-working online Xray proxy to test
        connectivity to the problematic servers.
        """
        # Find the share URL for the working Xray proxy
        working_name = getattr(working_xray_proxy, "name", "")
        working_host = getattr(working_xray_proxy, "server", "")
        working_port = getattr(working_xray_proxy, "port", 0)
        working_protocol = getattr(working_xray_proxy, "protocol", "").lower()

        working_share = find_share_url_for_proxy(
            self._subscription_shares,
            working_host,
            working_port,
            working_protocol,
            name=working_name,
        )

        if not working_share:
            log.warning(
                f"Could not find share URL for working Xray proxy: {working_name} ({working_host}:{working_port})"
            )
            return

        tasks = []
        for diag in problematic:
            # Parse host:port from diagnostic
            host_part = diag.host.rsplit(":", 1)
            if len(host_part) != 2:
                continue
            target_host = host_part[0]
            try:
                target_port = int(host_part[1])
            except ValueError:
                continue

            # Skip virtual hosts
            if target_host in ("virt.host", "localhost", "127.0.0.1"):
                continue

            # Only test proxies that failed Xray connectivity
            has_xray_failure = any(
                r.check_name.startswith("Proxy Xray Connectivity")
                and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
                for r in diag.results
            )
            if not has_xray_failure:
                continue

            # Find the protocol from diagnostic results
            protocol = "vless"  # default
            for r in diag.results:
                if r.check_name.startswith("Proxy Xray Connectivity"):
                    protocol = r.details.get("protocol", "vless")
                    break

            tasks.append(
                self._xray_cross_test_for_host(diag, target_host, target_port, protocol, working_share, working_name)
            )

        if tasks:
            log.info(f"Running {len(tasks)} Xray cross-proxy tests")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _xray_cross_test_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        target_port: int,
        target_protocol: str,
        working_share: ProxyShareURL,
        working_name: str,
    ) -> None:
        """Run a single Xray cross-proxy test and add result to diagnostic."""
        try:
            result = await check_xray_cross_connectivity(
                target_host,
                target_port,
                target_protocol,
                working_share,
                working_proxy_name=working_name,
            )
            diag.add_result(result)
            log.info(f"Xray cross-test {target_host}:{target_port} via {working_name}: {result.status.value}")
        except Exception as e:
            log.error(f"Xray cross-test failed for {target_host}:{target_port}: {e}")

    async def close(self) -> None:
        """Clean up resources."""
        await self.client.close()
