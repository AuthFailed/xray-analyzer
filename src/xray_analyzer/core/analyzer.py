"""Main analyzer that orchestrates all diagnostic checks."""

import asyncio
from ipaddress import ip_address
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
from xray_analyzer.diagnostics.proxy_rkn_throttle_checker import (
    check_rkn_throttle_direct,
    check_rkn_throttle_via_proxy,
    check_rkn_throttle_via_xray,
)
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
from xray_analyzer.diagnostics.xray_manager import XrayInstance
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

        # Run RKN throttle check on problematic hosts (direct connection test)
        if problematic and settings.rkn_throttle_check_enabled:
            await self._run_rkn_throttle_checks(problematic)

        # Run cross-proxy tests for problematic hosts
        if problematic and proxies:
            # 1. HTTP/SOCKS cross-test
            working_proxy = self._find_working_http_socks_proxy(proxies)
            if working_proxy:
                log.info(f"Found working proxy for cross-test: {working_proxy.server}:{working_proxy.port}")
                await self._run_cross_proxy_tests(problematic, working_proxy)

                # 2. RKN throttle check via working proxy (for hosts that failed direct throttle check)
                await self._run_rkn_throttle_via_proxy_tests(problematic, working_proxy)
            else:
                log.info("No working HTTP/SOCKS proxy found for cross-test")

            # 3. Xray cross-test (for VLESS/Trojan/SS proxies that failed)
            if self._subscription_shares:
                working_xray_proxy = self._find_working_xray_proxy(proxies)
                if working_xray_proxy:
                    log.info(f"Found working Xray proxy for cross-test: {working_xray_proxy.name}")
                    await self._run_xray_cross_proxy_tests(problematic, working_xray_proxy)

                    # 4. RKN throttle check via working Xray proxy
                    await self._run_rkn_throttle_via_xray_proxy_tests(problematic, working_xray_proxy)
                else:
                    log.info("No working Xray proxy found for cross-test")

        # Add smart recommendations based on cross-proxy tests
        for diag in problematic:
            self._add_blocking_recommendations(diag)

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
        except Exception as e:
            log.error(f"Xray cross-test failed for {target_host}:{target_port}: {e}")

    # === RKN Throttle Checks ===

    async def _run_rkn_throttle_checks(self, problematic: list[HostDiagnostic]) -> None:
        """
        Run RKN throttle checks on problematic hosts.

        For ALL proxies: checks the SNI domain directly (without proxy).
        For VLESS/Trojan with selfsteal: SNI = server domain.

        This detects DPI throttling (16-20KB cutoff) from our location.
        """
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

            # For VLESS/Trojan: get SNI from share URL if available
            is_xray_proxy = False
            protocol = None
            for r in diag.results:
                if r.check_name.startswith("Proxy Xray Connectivity"):
                    is_xray_proxy = True
                    protocol = r.details.get("protocol")
                    break

            if is_xray_proxy and self._subscription_shares:
                # Try to find share URL for SNI extraction
                proxy_name = ""
                for r in diag.results:
                    if r.check_name.startswith("Proxy Xray Connectivity"):
                        proxy_name = r.details.get("server", target_host)
                        break

                share = find_share_url_for_proxy(
                    self._subscription_shares,
                    target_host,
                    target_port,
                    protocol.lower() if protocol else "vless",
                    name=proxy_name,
                )

                if share:
                    # Extract SNI: sni > host header > server
                    sni_domain = share.sni or share.host or share.server
                    if sni_domain and sni_domain not in ("", "none") and sni_domain != target_host:
                        tasks.append(self._rkn_throttle_sni_for_host(diag, sni_domain, share))
                        continue
                        # else: SNI = server, check normally below

            # Default: check the server domain directly
            tasks.append(self._rkn_throttle_direct_for_host(diag, target_host, target_port))

        if tasks:
            log.info(f"Running {len(tasks)} RKN throttle checks (direct)")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _rkn_throttle_sni_for_host(
        self,
        diag: HostDiagnostic,
        sni_domain: str,
        share: ProxyShareURL,
    ) -> None:
        """Run RKN throttle check on the SNI domain from a share URL."""
        try:
            result = await check_rkn_throttle_direct(sni_domain, 443)
            # Add context to the result
            result.details["checked_for_proxy"] = f"{share.server}:{share.port}"
            result.details["share_name"] = share.name
            result.details["sni_domain"] = sni_domain
            diag.add_result(result)
        except Exception as e:
            log.error(f"RKN throttle SNI check failed for {sni_domain}: {e}")

    async def _rkn_throttle_direct_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        target_port: int,
    ) -> None:
        """Run a single RKN throttle check (direct connection)."""
        try:
            result = await check_rkn_throttle_direct(target_host, target_port)
            diag.add_result(result)
        except Exception as e:
            log.error(f"RKN throttle direct check failed for {target_host}:{target_port}: {e}")

    async def _run_rkn_throttle_via_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """
        Run RKN throttle checks through a working proxy.

        For VLESS/Trojan/SS: ALWAYS checks the SNI domain through working proxy
            (because direct check may timeout on VLESS-only servers).
        For HTTP/SOCKS: checks hosts that failed direct throttle check.

        This determines if the DPI throttling can be bypassed via proxy tunnel.
        """
        working_proxy_url = self._build_proxy_url(working_proxy)
        if not working_proxy_url:
            return

        working_name = getattr(working_proxy, "name", f"{working_proxy.server}:{working_proxy.port}")

        tasks = []
        for diag in problematic:
            # Parse host:port from diagnostic
            host_part = diag.host.rsplit(":", 1)
            if len(host_part) != 2:
                continue
            target_host = host_part[0]

            # Determine if this is a VLESS/Trojan/SS proxy
            is_xray_proxy = False
            for r in diag.results:
                if r.check_name.startswith("Proxy Xray Connectivity"):
                    is_xray_proxy = True
                    break

            if is_xray_proxy:
                # For VLESS/Trojan: ALWAYS check SNI domain through working proxy
                # For selfsteal, SNI = server domain (target_host)
                sni_domain = target_host
                tasks.append(self._rkn_throttle_via_proxy_for_host(diag, sni_domain, working_proxy_url, working_name))
            else:
                # For HTTP/SOCKS: only check if direct throttle check failed
                has_throttle_failure = any(
                    r.check_name.startswith("RKN Throttle") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
                    for r in diag.results
                )
                if has_throttle_failure:
                    tasks.append(
                        self._rkn_throttle_via_proxy_for_host(diag, target_host, working_proxy_url, working_name)
                    )

        if tasks:
            log.info(f"Running {len(tasks)} RKN throttle checks (via proxy: {working_name})")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _rkn_throttle_via_proxy_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        working_proxy_url: str,
        working_name: str,
    ) -> None:
        """Run a single RKN throttle check through a working proxy."""
        try:
            result = await check_rkn_throttle_via_proxy(working_proxy_url, target_host)
            diag.add_result(result)
        except Exception as e:
            log.error(f"RKN throttle proxy check failed for {target_host} via {working_name}: {e}")

    async def _run_rkn_throttle_via_xray_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_xray_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """
        Run RKN throttle checks through a working Xray proxy.

        This determines if the DPI throttling can be bypassed via Xray tunnel.
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
            # Only check hosts that failed the direct RKN throttle check
            has_throttle_failure = any(
                r.check_name.startswith("RKN Throttle") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
                for r in diag.results
            )
            if not has_throttle_failure:
                continue

            # Parse host:port from diagnostic
            host_part = diag.host.rsplit(":", 1)
            if len(host_part) != 2:
                continue
            target_host = host_part[0]

            tasks.append(self._xray_rkn_throttle_for_host(diag, target_host, working_share, working_name))

        if tasks:
            log.info(f"Running {len(tasks)} RKN throttle checks (via Xray: {working_name})")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _xray_rkn_throttle_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        working_share: ProxyShareURL,
        working_name: str,
    ) -> None:
        """Run RKN throttle check through Xray tunnel.

        Launches a working Xray proxy and checks if the target host
        is subject to DPI throttling (16-20KB cutoff) through the tunnel.
        """
        xray = XrayInstance(working_share)
        socks_port = 0

        try:
            socks_port = await xray.start()
        except RuntimeError as e:
            log.error(f"Failed to start Xray for throttle check: {e}")
            diag.add_result(
                DiagnosticResult(
                    check_name="RKN Throttle (via Xray)",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.WARNING,
                    message=f"Не удалось запустить Xray для проверки: {e}",
                    details={
                        "target_host": target_host,
                        "working_proxy": working_name,
                        "error": str(e),
                    },
                )
            )
            return

        socks_url = f"socks5://127.0.0.1:{socks_port}"

        try:
            result = await check_rkn_throttle_via_xray(
                socks_url=socks_url,
                sni_domain=target_host,
                share_name=working_name,
                label_suffix=f" (через {working_name})",
            )
            result.details["target_host"] = target_host
            diag.add_result(result)
        except Exception as e:
            log.error(f"Xray throttle check failed for {target_host} via {working_name}: {e}")
        finally:
            await xray.stop()

    async def close(self) -> None:
        """Clean up resources."""
        await self.client.close()

    # === Smart Recommendations Based on Cross-Proxy Tests ===

    def _add_blocking_recommendations(self, diag: HostDiagnostic) -> None:
        """
        Analyze cross-proxy test results to determine blocking type.

        Recommendations are tailored for VPN infrastructure operators,
        focusing on actionable fixes rather than "use another server".
        """
        # Prevent duplicate recommendations
        if diag.recommendations and any(
            "заблокирован" in r or "недоступен" in r or "троттлинг" in r.lower() for r in diag.recommendations
        ):
            return

        # Extract server domain and resolved IP from diagnostics
        server_domain = "unknown"
        server_ip = None

        for r in diag.results:
            # Get domain from the FIRST Xray connectivity test (domain test)
            if r.check_name.startswith("Proxy Xray Connectivity") and "домен:" in r.check_name:
                domain_in_label = r.check_name.split("домен:")[-1].strip().rstrip(")")
                if domain_in_label:
                    server_domain = domain_in_label
                # Also get server from details if it's a domain (not IP)
                srv = r.details.get("server", "")
                if srv:
                    try:
                        ip_address(srv)
                    except ValueError:
                        server_domain = srv

            # Get resolved IPs from DNS check
            if r.check_name.startswith("DNS Resolution"):
                local_ips = r.details.get("local_ips", [])
                if local_ips and not server_ip:
                    server_ip = local_ips[0]

            # Get IP from Xray IP fallback test
            if r.check_name.startswith("Proxy Xray Connectivity") and "IP:" in r.check_name:
                ip_in_label = r.check_name.split("IP:")[-1].strip().rstrip(")")
                if ip_in_label:
                    try:
                        ip_address(ip_in_label)
                        server_ip = ip_in_label
                    except ValueError:
                        pass
                # Also check details
                srv = r.details.get("server", "")
                if srv:
                    try:
                        ip_address(srv)
                        server_ip = srv
                    except ValueError:
                        pass

        # Extract cross-proxy status
        cross_proxy_result = None
        for r in diag.results:
            if r.check_name.startswith("Xray Cross-Proxy Connectivity"):
                cross_proxy_result = r
                break

        cross_proxy_name = cross_proxy_result.details.get("working_proxy", "") if cross_proxy_result else None
        cross_works = cross_proxy_result and cross_proxy_result.status == CheckStatus.PASS

        # Check 1: DNS Resolution failure — highest priority
        dns_failed = any(
            r.check_name.startswith("DNS Resolution") and r.status == CheckStatus.FAIL for r in diag.results
        )
        if dns_failed:
            diag.add_recommendation(f"🔒 DNS для {server_domain} не разрешается или не совпадает с Check-Host")
            diag.add_recommendation(
                "Причина: DNS poisoning или geo-blocking — локальный DNS возвращает другие IP, чем внешние ноды"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Использовать публичный DNS (Google 8.8.8.8, Cloudflare 1.1.1.1)\n"
                "  2) Настроить клиентов на подключение по IP напрямую\n"
                "  3) Сменить домен, если он попал в блокировки DNS-провайдеров"
            )
            return

        # Check 1.5: Xray connectivity passed but Exit IP/SNI failed
        # → Server works, but can't reach external services (routing/firewall issue)
        xray_connectivity_passed = any(
            r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS for r in diag.results
        )
        exit_ip_failed = any(
            r.check_name.startswith("Proxy Exit IP") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            for r in diag.results
        )
        sni_failed = any(
            r.check_name.startswith("Proxy SNI") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            for r in diag.results
        )

        if xray_connectivity_passed and (exit_ip_failed or sni_failed):
            failed_services = []
            if exit_ip_failed:
                failed_services.append("Exit IP check")
            if sni_failed:
                failed_services.append("SNI check")
            diag.add_recommendation(f"⚠️ Сервер {server_domain} подключается, но не достигает внешних сервисов")
            diag.add_recommendation(
                f"Причина: Xray подключился (HTTP 204), но {', '.join(failed_services)} провалились — "
                f"сервер не может достичь api.ipify.org или других внешних хостов"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Проверить маршрутизацию и firewall на сервере\n"
                "  2) Убедиться что сервер имеет доступ к внешнему интернету\n"
                "  3) Проверить DNS-настройки сервера (resolv.conf)\n"
                "  4) Возможно, сервер находится в NAT без внешнего доступа"
            )
            return

        # Check 2: RKN Throttle check — distinguish IP block vs DPI throttle
        # BUT only if Xray connectivity also failed (otherwise it's a different issue)
        xray_connectivity_failed = any(
            r.check_name.startswith("Proxy Xray Connectivity") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            for r in diag.results
        )

        for r in diag.results:
            if not r.check_name.startswith("RKN Throttle"):
                continue
            if r.status not in (CheckStatus.FAIL, CheckStatus.TIMEOUT):
                continue
            # Skip if Xray connectivity passed — this is a different issue (exit IP/SNI)
            if not xray_connectivity_failed:
                continue

            bytes_received = r.details.get("total_bytes_received", r.details.get("bytes_received", 0))

            if bytes_received == 0:
                # Outer timeout or 0 bytes → full block (not DPI throttle)
                ip_str = f"IP {server_ip}" if server_ip else server_domain
                if cross_works:
                    diag.add_recommendation(f"🔒 {ip_str} заблокирован для прямых подключений")
                    diag.add_recommendation(
                        f"Причина: 0 байт получено, но через {cross_proxy_name} работает — "
                        f"сервер рабочий, только прямые подключения заблокированы"
                    )
                else:
                    diag.add_recommendation(f"🚫 {ip_str} заблокирован РКН")
                    diag.add_recommendation("Причина: 0 байт получено — сервер не отвечает на запросы")
                diag.add_recommendation(
                    "Решения:\n"
                    "  1) Сменить IP-адрес сервера на новый из другой подсети\n"
                    "  2) Прокинуть мост (bridge) через рабочий прокси"
                )
            else:
                # 14-22KB received → DPI throttle
                kb_received = bytes_received / 1024
                diag.add_recommendation(f"🐌 Сервер {server_domain} — DPI-троттлинг ({kb_received:.0f}KB cutoff)")
                diag.add_recommendation(
                    f"Причина: РКН обрывает соединение после ~{kb_received:.0f}KB — "
                    "типичный паттерн DPI-фильтра (TLS ClientHello/SNI)"
                )
                diag.add_recommendation(
                    "Решения:\n"
                    "  1) Включить обфускацию транспорта (XHTTP/GRPC/WebSocket)\n"
                    "  2) Использовать VLESS + Reality с selfsteal-сертификатом\n"
                    "  3) Настроить TLS fingerprint под обычный веб-трафик (ja3)\n"
                    "  4) Подключаться через рабочий прокси-мост"
                )
            return

        # Now analyze cross-proxy connectivity results
        xray_domain_result = None
        xray_ip_result = None

        for r in diag.results:
            if r.check_name.startswith("Proxy Xray Connectivity") and "домен:" in r.check_name:
                xray_domain_result = r
            elif r.check_name.startswith("Proxy Xray Connectivity") and "IP:" in r.check_name:
                xray_ip_result = r

        # Skip if we don't have enough data
        if not xray_domain_result or not cross_proxy_result:
            return

        # Skip if direct tests passed
        if xray_domain_result.status == CheckStatus.PASS:
            return

        cross_status = cross_proxy_result.status

        # Case 3: Direct FAIL + IP FAIL + Cross PASS
        # → Server blocked for direct connections from our network/location
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and (xray_ip_result is None or xray_ip_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT))
            and cross_status == CheckStatus.PASS
        ):
            ip_str = f"IP {server_ip}" if server_ip else server_domain
            diag.add_recommendation(f"🔒 {ip_str} заблокирован для прямых подключений")
            diag.add_recommendation(
                f"Причина: не подключается напрямую, но через {cross_proxy_name} работает — "
                f"сервер рабочий, блокировка для нашей подсети"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Прокинуть мост (bridge) через рабочий прокси до сервера\n"
                "  2) Сменить IP-адрес сервера на новый из другой подсети"
            )
            return

        # Case 4: Direct (domain) FAIL + Direct (IP) PASS
        # → Domain-level block (DNS/SNI poisoning)
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and xray_ip_result
            and xray_ip_result.status == CheckStatus.PASS
        ):
            diag.add_recommendation(f"🔒 Домен {server_domain} заблокирован (DNS/SNI)")
            diag.add_recommendation(
                f"Причина: по домену не подключается, но по IP ({xray_ip_result.details.get('server', '')}) проходит"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Заменить домен на новый в конфигурации сервера\n"
                "  2) Настроить клиентов на подключение по IP вместо домена\n"
                "  3) Использовать SNI-обфускацию или selfsteal-сертификат"
            )
            return

        # Case 5: Direct FAIL + Cross FAIL
        # → IP-level block or server down entirely
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and (xray_ip_result is None or xray_ip_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT))
            and cross_status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        ):
            ip_str = f"IP {server_ip}" if server_ip else server_domain
            diag.add_recommendation(f"🚫 {ip_str} заблокирован или сервер недоступен")
            diag.add_recommendation(
                f"Причина: не работает ни напрямую, ни через {cross_proxy_name} — "
                f"сервер выключен или заблокирован глобально"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Проверить доступность сервера и перезапустить\n"
                "  2) Если сервер работает — сменить IP-адрес на новый\n"
                "  3) Проверить Xray-конфиг (UUID, порты, сертификаты)"
            )
            return
