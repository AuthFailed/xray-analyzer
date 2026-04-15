"""RKN throttle checking orchestrator — direct, via HTTP proxy, via Xray proxy."""

import asyncio

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
from xray_analyzer.diagnostics.proxy_rkn_throttle_checker import (
    check_rkn_throttle_direct,
    check_rkn_throttle_via_proxy,
    check_rkn_throttle_via_xray,
)
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL, find_share_url_for_proxy
from xray_analyzer.diagnostics.xray_manager import launched_xray

log = get_logger("throttle_checker")


class ThrottleCheckRunner:
    """Coordinates RKN throttle checks: direct, via proxy, via Xray tunnel."""

    def __init__(self, subscription_shares: list[ProxyShareURL]) -> None:
        self._subscription_shares = subscription_shares
        # Bound parallelism so a batch of 30+ problematic hosts doesn't fan out
        # into that many simultaneous HTTPS range-reads.
        self._sem = asyncio.Semaphore(settings.rkn_throttle_concurrency)

    async def _bounded(self, coro):  # type: ignore[no-untyped-def]
        async with self._sem:
            return await coro

    # --- Direct throttle checks ---

    async def run_direct_throttle_checks(self, problematic: list[HostDiagnostic]) -> None:
        """Run RKN throttle checks on problematic hosts (direct connection)."""
        tasks: list[asyncio.Task[None]] = []

        for diag in problematic:
            parsed = self._parse_host_port(diag)
            if parsed is None:
                continue
            target_host, target_port = parsed

            if target_host in ("virt.host", "localhost", "127.0.0.1"):
                continue

            # For VLESS/Trojan: check SNI domain from share URL
            is_xray_proxy = False
            protocol = None
            for r in diag.results:
                if r.check_name.startswith("Proxy Xray Connectivity"):
                    is_xray_proxy = True
                    protocol = r.details.get("protocol")
                    break

            if is_xray_proxy and self._subscription_shares:
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
                    sni_domain = share.sni or share.host or share.server
                    if sni_domain and sni_domain not in ("", "none") and sni_domain != target_host:
                        tasks.append(
                            asyncio.create_task(self._bounded(self._throttle_sni_for_host(diag, sni_domain, share)))
                        )
                    # else: SNI = server, check normally below

            tasks.append(
                asyncio.create_task(self._bounded(self._throttle_direct_for_host(diag, target_host, target_port)))
            )

        if tasks:
            log.info(f"Running {len(tasks)} RKN throttle checks (direct)")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _throttle_sni_for_host(
        self,
        diag: HostDiagnostic,
        sni_domain: str,
        share: ProxyShareURL,
    ) -> None:
        """Run RKN throttle check on the SNI domain from a share URL."""
        try:
            result = await check_rkn_throttle_direct(sni_domain, 443)
            result.details["checked_for_proxy"] = f"{share.server}:{share.port}"
            result.details["share_name"] = share.name
            result.details["sni_domain"] = sni_domain
            diag.add_result(result)
        except Exception as e:
            log.error(f"RKN throttle SNI check failed for {sni_domain}: {e}")

    async def _throttle_direct_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        target_port: int,
    ) -> None:
        """Run a single RKN throttle check (direct connection).

        Throttle detection is an HTTPS-layer test (16-20 KB cutoff via RST injection),
        so it only makes sense against port 443. Using the proxy's service port
        (e.g. 8388 for Shadowsocks) would trigger a TLS handshake failure that looks
        like throttling but is just a protocol mismatch — a false positive.
        """
        if target_port != 443:
            log.debug(
                f"Skipping direct throttle check for {target_host}:{target_port} "
                f"(non-443 port, would yield false positive)"
            )
            return

        try:
            result = await check_rkn_throttle_direct(target_host, target_port)
            diag.add_result(result)
        except Exception as e:
            log.error(f"RKN throttle direct check failed for {target_host}:{target_port}: {e}")

    # --- Throttle checks via HTTP/SOCKS proxy ---

    async def run_throttle_via_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """Run RKN throttle checks through a working HTTP/SOCKS proxy."""
        working_proxy_url = self._build_proxy_url(working_proxy)
        if not working_proxy_url:
            return

        working_name = getattr(working_proxy, "name", f"{working_proxy.server}:{working_proxy.port}")

        tasks: list[asyncio.Task[None]] = []
        for diag in problematic:
            parsed = self._parse_host_port(diag)
            if parsed is None:
                continue
            target_host = parsed[0]

            # Determine if this is a VLESS/Trojan/SS proxy
            is_xray_proxy = False
            for r in diag.results:
                if r.check_name.startswith("Proxy Xray Connectivity"):
                    is_xray_proxy = True
                    break

            if is_xray_proxy:
                # For VLESS/Trojan: ALWAYS check SNI domain through working proxy
                sni_domain = target_host
                tasks.append(
                    asyncio.create_task(
                        self._bounded(
                            self._throttle_via_proxy_for_host(diag, sni_domain, working_proxy_url, working_name)
                        )
                    )
                )
            else:
                # For HTTP/SOCKS: only check if direct throttle check failed
                has_throttle_failure = any(
                    r.check_name.startswith("RKN Throttle") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
                    for r in diag.results
                )
                if has_throttle_failure:
                    tasks.append(
                        asyncio.create_task(
                            self._bounded(
                                self._throttle_via_proxy_for_host(diag, target_host, working_proxy_url, working_name)
                            )
                        )
                    )

        if tasks:
            log.info(f"Running {len(tasks)} RKN throttle checks (via proxy: {working_name})")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _throttle_via_proxy_for_host(
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

    # --- Throttle checks via Xray proxy ---

    async def run_throttle_via_xray_proxy_tests(
        self,
        problematic: list[HostDiagnostic],
        working_xray_proxy: ProxyInfo | ProxyStatus,
    ) -> None:
        """Run RKN throttle checks through a working Xray proxy."""
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

        targets: list[tuple[HostDiagnostic, str]] = []
        for diag in problematic:
            has_throttle_failure = any(
                r.check_name.startswith("RKN Throttle") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
                for r in diag.results
            )
            if not has_throttle_failure:
                continue

            parsed = self._parse_host_port(diag)
            if parsed is None:
                continue

            targets.append((diag, parsed[0]))

        if not targets:
            return

        log.info(f"Running {len(targets)} RKN throttle checks through shared Xray ({working_name})")
        try:
            async with launched_xray(working_share) as socks_url:
                await asyncio.gather(
                    *[self._bounded(self._xray_throttle_for_host(diag, target_host, socks_url, working_name))
                      for diag, target_host in targets],
                    return_exceptions=True,
                )
        except RuntimeError as e:
            log.error(f"Failed to start Xray for throttle checks: {e}")
            for diag, target_host in targets:
                diag.add_result(
                    DiagnosticResult(
                        check_name="RKN Throttle (via Xray)",
                        status=CheckStatus.SKIP,
                        severity=CheckSeverity.WARNING,
                        message=f"Failed to start Xray for check: {e}",
                        details={
                            "target_host": target_host,
                            "working_proxy": working_name,
                            "error": str(e),
                        },
                    )
                )

    async def _xray_throttle_for_host(
        self,
        diag: HostDiagnostic,
        target_host: str,
        socks_url: str,
        working_name: str,
    ) -> None:
        """Run RKN throttle check through a shared Xray tunnel."""
        try:
            result = await check_rkn_throttle_via_xray(
                socks_url=socks_url,
                sni_domain=target_host,
                share_name=working_name,
                label_suffix=f" (via {working_name})",
            )
            result.details["target_host"] = target_host
            diag.add_result(result)
        except Exception as e:
            log.error(f"Xray throttle check failed for {target_host} via {working_name}: {e}")

    # --- Utility ---

    @staticmethod
    def _build_proxy_url(proxy: ProxyInfo | ProxyStatus) -> str | None:
        """Build a proxy URL from proxy info."""
        if hasattr(proxy, "server") and hasattr(proxy, "port"):
            protocol = getattr(proxy, "protocol", "http").lower()
            return f"{protocol}://{proxy.server}:{proxy.port}"
        return None

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
