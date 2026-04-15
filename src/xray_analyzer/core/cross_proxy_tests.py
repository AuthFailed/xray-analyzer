"""Cross-proxy testing engine — tests problematic hosts through working proxies."""

import asyncio
from typing import Any

import aiohttp

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import (
    CheckSeverity,
    CheckStatus,
    DiagnosticResult,
    HostDiagnostic,
    ProxyInfo,
    ProxyStatus,
)
from xray_analyzer.diagnostics.proxy_cross_checker import (
    check_via_proxy,
    check_xray_cross_connectivity,
)
from xray_analyzer.diagnostics.proxy_xray_checker import XRAY_PROTOCOLS
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL, find_share_url_for_proxy
from xray_analyzer.diagnostics.xray_manager import launched_xray

log = get_logger("cross_proxy_tests")


class CrossProxyTestRunner:
    """Coordinates cross-proxy tests: connectivity through working proxies."""

    def __init__(self, subscription_shares: list[ProxyShareURL]) -> None:
        self._subscription_shares = subscription_shares

    # --- Working proxy discovery ---

    def find_working_http_socks_proxy(self, proxies: list[ProxyInfo | ProxyStatus]) -> ProxyInfo | ProxyStatus | None:
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

    def find_working_xray_proxy(self, proxies: list[ProxyInfo | ProxyStatus]) -> ProxyInfo | ProxyStatus | None:
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

    # --- HTTP/SOCKS cross-proxy tests ---

    @staticmethod
    def _build_proxy_url(proxy: Any) -> str | None:
        """Build a proxy URL from proxy info."""
        if hasattr(proxy, "server") and hasattr(proxy, "port"):
            protocol = getattr(proxy, "protocol", "http").lower()
            return f"{protocol}://{proxy.server}:{proxy.port}"
        return None

    async def run_cross_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """Test connectivity to problematic hosts through a working proxy."""
        working_proxy_url = self._build_proxy_url(working_proxy)
        if not working_proxy_url:
            return

        working_name = getattr(working_proxy, "name", f"{working_proxy.server}:{working_proxy.port}")

        tasks = []
        for diag in problematic:
            parsed = self._parse_host_port(diag)
            if parsed is None:
                continue
            target_host, target_port = parsed

            if target_host in ("virt.host", "localhost", "127.0.0.1"):
                continue

            tasks.append(self._cross_test_for_host(diag, target_host, target_port, working_proxy_url, working_name))

        if tasks:
            log.info(f"Running {len(tasks)} cross-proxy tests (HTTP/SOCKS)")
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

    # --- Xray cross-proxy tests ---

    async def run_xray_cross_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_xray_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """Test connectivity to problematic Xray proxies through a working Xray proxy."""
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

        # Collect work items first; start Xray only if there is something to do.
        work: list[tuple[HostDiagnostic, str, int, str]] = []
        for diag in problematic:
            parsed = self._parse_host_port(diag)
            if parsed is None:
                continue
            target_host, target_port = parsed

            if target_host in ("virt.host", "localhost", "127.0.0.1"):
                continue

            has_xray_failure = any(
                r.check_name.startswith("Proxy Xray Connectivity")
                and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
                for r in diag.results
            )
            if not has_xray_failure:
                continue

            protocol = "vless"
            for r in diag.results:
                if r.check_name.startswith("Proxy Xray Connectivity"):
                    protocol = r.details.get("protocol", "vless")
                    break

            work.append((diag, target_host, target_port, protocol))

        if not work:
            return

        log.info(f"Running {len(work)} Xray cross-proxy tests through shared {working_name}")
        try:
            async with launched_xray(working_share) as socks_url, aiohttp.ClientSession() as session:
                await asyncio.gather(
                    *[
                        self._xray_cross_test_for_host(
                            diag, target_host, target_port, protocol, socks_url, working_share.protocol, working_name,
                            session,
                        )
                        for diag, target_host, target_port, protocol in work
                    ],
                    return_exceptions=True,
                )
        except RuntimeError as e:
            log.error(f"Failed to start shared working Xray proxy for cross-tests: {e}")
            for diag, target_host, target_port, protocol in work:
                diag.add_result(
                    DiagnosticResult(
                        check_name="Xray Cross-Proxy Connectivity",
                        status=CheckStatus.SKIP,
                        severity=CheckSeverity.WARNING,
                        message=f"Не удалось запустить рабочий прокси для проверки: {e}",
                        details={
                            "target_host": target_host,
                            "target_port": target_port,
                            "target_protocol": protocol,
                            "working_proxy": working_name,
                            "error": str(e),
                        },
                    )
                )

    async def _xray_cross_test_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        target_port: int,
        target_protocol: str,
        socks_url: str,
        working_protocol: str,
        working_name: str,
        session: aiohttp.ClientSession,
    ) -> None:
        """Run a single Xray cross-proxy test and add result to diagnostic."""
        try:
            result = await check_xray_cross_connectivity(
                target_host,
                target_port,
                target_protocol,
                socks_url,
                working_proxy_name=working_name,
                working_proxy_protocol=working_protocol,
                session=session,
            )
            diag.add_result(result)
        except Exception as e:
            log.error(f"Xray cross-test failed for {target_host}:{target_port}: {e}")

    # --- Utility ---

    @staticmethod
    def _parse_host_port(diag: HostDiagnostic) -> tuple[str, int] | None:
        """Parse host:port from a HostDiagnostic."""
        host_part = diag.host.rsplit(":", 1)
        if len(host_part) != 2:
            return None
        try:
            return host_part[0], int(host_part[1])
        except ValueError:
            return None
