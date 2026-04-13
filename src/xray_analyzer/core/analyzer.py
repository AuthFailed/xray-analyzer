"""Main analyzer that orchestrates all diagnostic checks."""

import asyncio
from typing import Any

from xray_analyzer.core.config import settings
from xray_analyzer.core.cross_proxy_tests import CrossProxyTestRunner
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import (
    CheckSeverity,
    CheckStatus,
    DiagnosticResult,
    HostDiagnostic,
    ProxyInfo,
    ProxyStatus,
)
from xray_analyzer.core.recommendation_engine import RecommendationEngine
from xray_analyzer.core.throttle_checker_runner import ThrottleCheckRunner
from xray_analyzer.core.xray_client import XrayCheckerClient
from xray_analyzer.diagnostics.dns_checker import check_dns_with_checkhost
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
        self._cross_proxy_runner = CrossProxyTestRunner(self._subscription_shares)
        self._throttle_runner = ThrottleCheckRunner(self._subscription_shares)
        self._recommendation_engine = RecommendationEngine()

    async def run_full_analysis(self) -> list[HostDiagnostic]:
        """
        Run complete diagnostic analysis on all proxies.

        By default, only analyzes offline proxies. Set ANALYZE_ONLINE_PROXIES=true
        in .env to analyze all proxies.

        Returns list of HostDiagnostic objects for each problematic host.
        """
        log.info("Starting full analysis")

        # Load subscription share URLs (for VLESS/Trojan/SS testing)
        await self._load_subscription_shares()

        # Ensure Xray binary is available if testing VLESS/Trojan/SS
        await self._ensure_xray_binary()

        # Get all proxies from checker API
        proxies = await self._get_proxies()
        if not proxies:
            log.warning("No proxies found from checker API")
            return []

        # Filter to only offline proxies by default
        offline_only = not getattr(settings, "analyze_online_proxies", False)
        targets = [p for p in proxies if not p.online] if offline_only else proxies  # type: ignore

        if not targets:
            log.info("No proxies to analyze — all are online")
            return []

        log.info(
            f"Found {len(targets)} proxies to analyze out of {len(proxies)} total"
            if offline_only
            else f"Found {len(proxies)} proxies to analyze"
        )

        # Run diagnostics on each proxy
        diagnostics = await self._analyze_all_proxies(targets)

        # Filter to only problematic hosts
        problematic = [d for d in diagnostics if d.overall_status not in (CheckStatus.PASS, CheckStatus.WARN)]

        # Run RKN throttle checks on problematic hosts (direct connection test)
        if problematic and settings.rkn_throttle_check_enabled:
            await self._throttle_runner.run_direct_throttle_checks(problematic)

        # Run cross-proxy tests for problematic hosts
        if problematic and proxies:
            await self._run_cross_proxy_tests(problematic, proxies)

        # Add smart recommendations based on cross-proxy tests
        for diag in problematic:
            self._recommendation_engine.add_blocking_recommendations(diag)

        log.info(f"Analysis complete: {len(problematic)} problematic out of {len(diagnostics)} total")

        # Send notifications if there are problems
        if problematic:
            await self.notifier_manager.notify(diagnostics)

        return diagnostics

    async def run_single_host_analysis(
        self, host: str, port: int = 443, proxy_url: str = ""
    ) -> HostDiagnostic:
        """Run diagnostic analysis on a single host."""
        log.info(f"Starting analysis for {host}:{port}")
        diagnostic = HostDiagnostic(host=f"{host}:{port}")

        await self._run_all_checks(diagnostic, host, port, None, direct_proxy_url=proxy_url)

        return diagnostic

    # --- Initialization helpers ---

    async def _load_subscription_shares(self) -> None:
        """Load subscription share URLs if configured."""
        if not settings.subscription_url or not settings.xray_test_enabled:
            return
        try:
            self._subscription_shares = await fetch_subscription(
                settings.subscription_url,
                hwid=settings.subscription_hwid,
            )
            log.info(f"Loaded {len(self._subscription_shares)} proxies from subscription")
            for s in self._subscription_shares:
                log.info(f"  Share: {s.name} | {s.server}:{s.port} | {s.protocol}")
            # Re-initialize runners with loaded shares
            self._cross_proxy_runner = CrossProxyTestRunner(self._subscription_shares)
            self._throttle_runner = ThrottleCheckRunner(self._subscription_shares)
        except Exception as e:
            log.warning(f"Failed to load subscription: {e}")

    async def _ensure_xray_binary(self) -> None:
        """Ensure Xray binary is available if testing VLESS/Trojan/SS."""
        if not settings.xray_test_enabled:
            return
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

    # --- Proxy fetching ---

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

    # --- Per-proxy analysis ---

    async def _analyze_all_proxies(self, targets: list[ProxyInfo | ProxyStatus]) -> list[HostDiagnostic]:
        """Run diagnostic analysis on all target proxies concurrently."""
        tasks = [self._analyze_proxy(proxy) for proxy in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        diagnostics: list[HostDiagnostic] = []
        for result in results:
            if isinstance(result, Exception):
                log.error(f"Error during analysis: {result}", exc_info=result)
            elif isinstance(result, HostDiagnostic):
                diagnostics.append(result)
        return diagnostics

    async def _analyze_proxy(self, proxy: ProxyInfo | ProxyStatus) -> HostDiagnostic:
        """Run all diagnostic checks on a single proxy."""
        # Get real server address from full proxy info
        if hasattr(proxy, "server"):
            host = proxy.server  # type: ignore
            port = proxy.port  # type: ignore
        else:
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
                "Configure authentication (CHECKER_API_USERNAME/PASSWORD) to obtain server addresses"
            )
            return diagnostic

        # Skip virtual host placeholders entirely
        virtual_hosts = {"virt.host", "localhost", "127.0.0.1"}
        if host in virtual_hosts:
            log.debug(f"Skipping virtual host '{host}' for proxy {proxy.stable_id} ({proxy.name})")
            return HostDiagnostic(host=f"{host}:{port}")

        log.info(f"Analyzing proxy: {proxy.name} → {host}:{port}")
        diagnostic = HostDiagnostic(host=f"{host}:{port}")

        await self._run_all_checks(diagnostic, host, port, proxy, direct_proxy_url="")

        return diagnostic

    # --- Running all checks ---

    async def _run_all_checks(
        self,
        diagnostic: HostDiagnostic,
        host: str,
        port: int,
        proxy: Any,
        direct_proxy_url: str = "",
    ) -> None:
        """Run all diagnostic checks and add results to diagnostic."""
        # 1. DNS Resolution with Check-Host.net comparison
        dns_result = await check_dns_with_checkhost(host)
        diagnostic.add_result(dns_result)

        if dns_result.status == CheckStatus.FAIL:
            diagnostic.add_recommendation("DNS cannot be resolved — check domain and DNS settings")

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
            for ip_addr in resolved_ips[:2]:
                ip_rkn_result = await check_rkn_blocking(ip_addr)
                diagnostic.add_result(ip_rkn_result)

        # Proxy-specific checks — either from API proxy object or direct --proxy URL
        if not proxy and direct_proxy_url:
            # First: confirm target host is reachable through the given proxy
            target_result = await check_via_proxy(host, port, direct_proxy_url, proxy_name=direct_proxy_url)
            target_result = target_result.model_copy(update={"check_name": "Target via Proxy"})
            diagnostic.add_result(target_result)

            tunnel_result = await check_proxy_tcp_tunnel(direct_proxy_url)
            diagnostic.add_result(tunnel_result)

            exit_ip_result = await check_proxy_exit_ip(direct_proxy_url)
            diagnostic.add_result(exit_ip_result)

            if settings.proxy_sni_test_enabled:
                sni_result = await check_proxy_sni_connection(direct_proxy_url)
                diagnostic.add_result(sni_result)

            if settings.tunnel_test_enabled:
                legacy_tunnel_result = await check_proxy_tunnel(direct_proxy_url)
                diagnostic.add_result(legacy_tunnel_result)

        if proxy:
            await self._run_proxy_specific_checks(diagnostic, host, port, proxy, dns_result)

    async def _run_proxy_specific_checks(
        self,
        diagnostic: HostDiagnostic,
        host: str,
        port: int,
        proxy: Any,
        dns_result: DiagnosticResult,
    ) -> None:
        """Run protocol-specific checks (Xray or HTTP/SOCKS)."""
        protocol = getattr(proxy, "protocol", "http").lower()

        if protocol in XRAY_PROTOCOLS and self._subscription_shares:
            await self._run_xray_proxy_checks(diagnostic, host, port, protocol, proxy, dns_result)
        elif protocol in XRAY_PROTOCOLS:
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="Proxy Xray Test",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message=f"SUBSCRIPTION_URL is required in configuration for {protocol}",
                    details={"protocol": protocol, "server": host},
                    recommendations=[
                        "Set SUBSCRIPTION_URL to test VLESS/Trojan/SS proxies",
                        "Or use xray-checker API to check proxy status",
                    ],
                )
            )
        else:
            await self._run_http_socks_proxy_checks(diagnostic, proxy)

    async def _run_xray_proxy_checks(
        self,
        diagnostic: HostDiagnostic,
        host: str,
        port: int,
        protocol: str,
        proxy: Any,
        dns_result: DiagnosticResult,
    ) -> None:
        """Run Xray-based proxy tests."""
        proxy_name = getattr(proxy, "name", "")
        share = find_share_url_for_proxy(self._subscription_shares, host, port, protocol, name=proxy_name)
        if not share:
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="Proxy Xray Test",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.WARNING,
                    message=f"Share URL not found for {host}:{port} ({protocol}) in subscription",
                    details={"protocol": protocol, "server": host, "port": port},
                    recommendations=[
                        "Check that the subscription URL contains this proxy",
                        "Make sure SUBSCRIPTION_URL is configured correctly",
                    ],
                )
            )
            return

        local_ips: list[str] = []
        if dns_result.status == CheckStatus.PASS:
            local_ips = dns_result.details.get("local_ips", [])
        fallback_ip = local_ips[0] if local_ips else None

        xray_results = await check_proxy_via_xray(share, fallback_server_ip=fallback_ip)
        for result in xray_results:
            diagnostic.add_result(result)

    async def _run_http_socks_proxy_checks(
        self,
        diagnostic: HostDiagnostic,
        proxy: Any,
    ) -> None:
        """Run HTTP/SOCKS proxy tests."""
        proxy_url = self._build_proxy_url(proxy)
        if not proxy_url:
            return

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

    @staticmethod
    def _build_proxy_url(proxy: Any) -> str | None:
        """Build a proxy URL from proxy info."""
        if hasattr(proxy, "server") and hasattr(proxy, "port"):
            protocol = getattr(proxy, "protocol", "http").lower()
            return f"{protocol}://{proxy.server}:{proxy.port}"
        return None

    # --- Cross-proxy tests coordination ---

    async def _run_cross_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        proxies: list[ProxyInfo | ProxyStatus],
    ) -> None:
        """Run all types of cross-proxy tests."""
        # 1. HTTP/SOCKS cross-test
        working_proxy = self._cross_proxy_runner.find_working_http_socks_proxy(proxies)
        if working_proxy:
            log.info(f"Found working proxy for cross-test: {working_proxy.server}:{working_proxy.port}")
            await self._cross_proxy_runner.run_cross_proxy_tests(problematic, working_proxy)

            # 2. RKN throttle check via working proxy
            await self._throttle_runner.run_throttle_via_proxy_tests(problematic, working_proxy)
        else:
            log.info("No working HTTP/SOCKS proxy found for cross-test")

        # 3. Xray cross-test (for VLESS/Trojan/SS proxies that failed)
        if not self._subscription_shares:
            return

        working_xray_proxy = self._cross_proxy_runner.find_working_xray_proxy(proxies)
        if working_xray_proxy:
            log.info(f"Found working Xray proxy for cross-test: {working_xray_proxy.name}")
            await self._cross_proxy_runner.run_xray_cross_proxy_tests(problematic, working_xray_proxy)

            # 4. RKN throttle check via working Xray proxy
            await self._throttle_runner.run_throttle_via_xray_proxy_tests(problematic, working_xray_proxy)
        else:
            log.info("No working Xray proxy found for cross-test")

    # --- Cleanup ---

    async def close(self) -> None:
        """Clean up resources."""
        await self.client.close()
