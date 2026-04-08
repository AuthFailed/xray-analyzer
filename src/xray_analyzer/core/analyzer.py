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
from xray_analyzer.diagnostics.dns_checker import check_dns_resolution
from xray_analyzer.diagnostics.rkn_checker import check_rkn_blocking, extract_domain_from_url
from xray_analyzer.diagnostics.tcp_checker import check_tcp_connection
from xray_analyzer.diagnostics.tunnel_checker import check_proxy_tunnel
from xray_analyzer.notifiers.manager import NotifierManager

log = get_logger("analyzer")


class XrayAnalyzer:
    """Main analyzer that orchestrates all diagnostic checks."""

    def __init__(self) -> None:
        self.client = XrayCheckerClient()
        self.notifier_manager = NotifierManager()

    async def run_full_analysis(self) -> list[HostDiagnostic]:
        """
        Run complete diagnostic analysis on all proxies.

        By default, only analyzes offline proxies. Set ANALYZE_ONLINE_PROXIES=true
        in .env to analyze all proxies.

        Returns list of HostDiagnostic objects for each problematic host.
        """
        log.info("Starting full analysis")

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

        log.info(
            f"Analysis complete: {len(problematic)} problematic out of {len(diagnostics)} total"
        )

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
                        f"Checker API unavailable (attempt {attempt}/{max_retries}), "
                        f"retrying in {retry_delay}s: {e}"
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

        # Skip DNS/TCP for virtual host placeholders
        virtual_hosts = {"virt.host", "localhost", "127.0.0.1"}
        is_virtual = host in virtual_hosts

        # 1. DNS Resolution (skip for virtual hosts)
        if is_virtual:
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="DNS Resolution",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message=f"Виртуальный хост '{host}' — DNS проверка пропущена",
                    details={"host": host, "is_virtual": True},
                )
            )
        else:
            dns_result = await check_dns_resolution(host)
            diagnostic.add_result(dns_result)

            # If DNS fails, skip other network checks
            if dns_result.status == CheckStatus.FAIL:
                diagnostic.add_recommendation(
                    "DNS не разрешается — проверьте домен и DNS-настройки"
                )
                return

        # 2. TCP Connection (skip for virtual hosts)
        if is_virtual:
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="TCP Connection",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message=f"Виртуальный хост '{host}' — TCP проверка пропущена",
                    details={"host": host, "is_virtual": True},
                )
            )
        else:
            tcp_result = await check_tcp_connection(host, port)
            diagnostic.add_result(tcp_result)

        # 3. RKN Block Check (extract domain from host)
        domain = extract_domain_from_url(host) if "://" in host else host
        rkn_result = await check_rkn_blocking(domain)
        diagnostic.add_result(rkn_result)

        # 4. Proxy Tunnel Check (if proxy URL is available)
        if settings.tunnel_test_enabled and proxy:
            proxy_url = self._build_proxy_url(proxy)
            if proxy_url:
                tunnel_result = await check_proxy_tunnel(proxy_url)
                diagnostic.add_result(tunnel_result)

    def _build_proxy_url(self, proxy: Any) -> str | None:
        """Build a proxy URL from proxy info."""
        if hasattr(proxy, "server") and hasattr(proxy, "port"):
            protocol = getattr(proxy, "protocol", "http").lower()
            return f"{protocol}://{proxy.server}:{proxy.port}"
        return None

    async def close(self) -> None:
        """Clean up resources."""
        await self.client.close()
