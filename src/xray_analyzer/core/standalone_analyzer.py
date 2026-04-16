"""Standalone analyzer for testing proxies from subscription without checker API."""

import asyncio
import re
from collections.abc import Callable
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
from xray_analyzer.diagnostics.dns_checker import check_dns_with_checkhost, close_dns_session
from xray_analyzer.diagnostics.proxy_cross_checker import check_xray_cross_connectivity
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


ProxyCompleteCallback = Callable[[HostDiagnostic, "ProxyShareURL"], None]
PhaseCallback = Callable[[str, int], None]


class _DirectProbeCache:
    """Dedupe direct DNS / TCP / Ping checks by (host, port) within one run.

    Subscriptions frequently list multiple proxies that share the same backing
    server (e.g. six `r.xodsit.com:443` entries for different exit countries).
    Without this cache, those six analyses fire six parallel TCP handshakes and
    six parallel TCP pings at the same server, which trips CDN rate-limiters
    and creates phantom packet-loss / latency-spike noise in the report.

    The cache stores *futures*, not resolved results, so concurrent callers
    from different proxies all await the same in-flight probe and receive an
    identical DiagnosticResult.
    """

    def __init__(self) -> None:
        self._dns: dict[str, asyncio.Task[DiagnosticResult]] = {}
        self._tcp: dict[tuple[str, int], asyncio.Task[DiagnosticResult]] = {}
        self._ping: dict[tuple[str, int], asyncio.Task[DiagnosticResult]] = {}

    def dns(self, host: str) -> asyncio.Task[DiagnosticResult]:
        task = self._dns.get(host)
        if task is None:
            task = asyncio.create_task(check_dns_with_checkhost(host), name=f"cached-dns:{host}")
            self._dns[host] = task
        return task

    def tcp(self, host: str, port: int) -> asyncio.Task[DiagnosticResult]:
        key = (host, port)
        task = self._tcp.get(key)
        if task is None:
            task = asyncio.create_task(check_tcp_connection(host, port), name=f"cached-tcp:{host}:{port}")
            self._tcp[key] = task
        return task

    def ping(self, host: str, port: int) -> asyncio.Task[DiagnosticResult]:
        key = (host, port)
        task = self._ping.get(key)
        if task is None:
            task = asyncio.create_task(check_tcp_ping(host, port), name=f"cached-ping:{host}:{port}")
            self._ping[key] = task
        return task


async def analyze_subscription_proxies(
    shares: list[ProxyShareURL],
    on_proxy_complete: ProxyCompleteCallback | None = None,
    on_phase: PhaseCallback | None = None,
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
        on_proxy_complete: optional callback fired after each proxy finishes
            (receives the HostDiagnostic and the share). Used by the CLI to
            stream live progress under a Rich progress bar.

    Returns:
        List of HostDiagnostic for each proxy
    """
    log.info(f"Starting standalone analysis of {len(shares)} proxies")

    try:
        # Build a host-label → share map so the per-proxy callback can recover
        # the original share even though asyncio.as_completed yields anonymous
        # awaitables (not the original task objects).
        share_by_label = {f"{s.name} ({s.server}:{s.port})": s for s in shares}

        # One shared probe cache for the whole run — see _DirectProbeCache docstring.
        probe_cache = _DirectProbeCache()

        async def _wrapped(share: ProxyShareURL) -> HostDiagnostic:
            return await analyze_single_proxy(share, probe_cache=probe_cache)

        coros = [_wrapped(share) for share in shares]

        diagnostics: list[HostDiagnostic] = []
        for completed in asyncio.as_completed(coros):
            try:
                result = await completed
            except Exception as exc:
                log.error(f"Error during analysis: {exc}", exc_info=exc)
                continue
            if not isinstance(result, HostDiagnostic):
                continue
            diagnostics.append(result)
            if on_proxy_complete is not None:
                share = share_by_label.get(result.host)
                if share is not None:
                    try:
                        on_proxy_complete(result, share)
                    except Exception as cb_exc:
                        log.warning(f"on_proxy_complete callback raised: {cb_exc}")

        # Run cross-proxy tests for problematic hosts
        problematic = [d for d in diagnostics if d.overall_status != CheckStatus.PASS]
        if problematic:
            if on_phase is not None:
                try:
                    on_phase("cross_proxy", len(problematic))
                except Exception as cb_exc:
                    log.warning(f"on_phase callback raised: {cb_exc}")
            await _run_standalone_cross_tests(problematic, shares, diagnostics)

        if on_phase is not None:
            try:
                on_phase("finalizing", 0)
            except Exception as cb_exc:
                log.warning(f"on_phase callback raised: {cb_exc}")

        log.info(f"Standalone analysis complete: {len(diagnostics)} proxies analyzed")
        return diagnostics
    finally:
        # The DNS check uses a shared aiohttp session — close it so we don't leak.
        await close_dns_session()


async def analyze_single_proxy(
    share: ProxyShareURL,
    probe_cache: _DirectProbeCache | None = None,
) -> HostDiagnostic:
    """Run all diagnostic checks on a single proxy.

    When `probe_cache` is provided, DNS / TCP Connect / TCP Ping results are
    looked up (or computed once and memoized) keyed by the backing server —
    so six proxies that share e.g. `r.xodsit.com:443` all reuse a single
    probe result instead of stampeding the server.
    """
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

    cache = probe_cache if probe_cache is not None else _DirectProbeCache()

    # 1. DNS Resolution (shared across proxies with the same host)
    dns_result = await cache.dns(host)
    diagnostic.add_result(dns_result)

    # 2. TCP Connection (shared across proxies with the same host:port)
    tcp_result = await cache.tcp(host, port)
    diagnostic.add_result(tcp_result)

    # 3. TCP Ping — only if TCP Connection passed. When TCP Connection has
    #    already timed out, running more probes just repeats the same failure
    #    and can trigger rate limits that create phantom loss.
    if tcp_result.status == CheckStatus.PASS:
        tcp_ping_result = await cache.ping(host, port)
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
                    message=f"Xray testing disabled (--no-xray). Testing {share.protocol} requires Xray core",
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

    # Re-evaluate overall status using authoritative signals (proxy works → not FAIL)
    diagnostic.finalize_status()

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
        diagnostic.add_recommendation(f"⚠️ DNS for {server_domain} doesn't match Check-Host (geo-blocking)")
        diagnostic.add_recommendation("Local DNS returns different IPs than external Check-Host.net nodes")

    # Check if Xray connectivity passed but Exit IP/SNI failed
    xray_connectivity_passed = any(
        r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS for r in results
    )
    exit_ip_failed = any(
        r.check_name.startswith("Proxy Exit IP") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        for r in results
    )
    sni_failed = any(
        r.check_name.startswith("Proxy SNI") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT) for r in results
    )

    if xray_connectivity_passed and (exit_ip_failed or sni_failed):
        failed_services = []
        if exit_ip_failed:
            failed_services.append("Exit IP check")
        if sni_failed:
            failed_services.append("SNI check")
        diagnostic.add_recommendation(f"⚠️ Server {server_domain} connects but cannot reach external services")
        diagnostic.add_recommendation(
            f"Reason: Xray connected (HTTP 204) but {', '.join(failed_services)} failed — "
            f"server cannot reach external hosts"
        )
        diagnostic.add_recommendation(
            "Solutions:\n"
            "  1) Check routing and firewall on the server\n"
            "  2) Make sure the server has internet access\n"
            "  3) Check DNS settings on the server (resolv.conf)"
        )

    # Xray connectivity failed but IP fallback worked
    xray_domain_failed = any(
        r.check_name.startswith("Proxy Xray Connectivity")
        and ("домен:" in r.check_name or "domain:" in r.check_name)
        and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        for r in results
    )
    xray_ip_passed = any(
        r.check_name.startswith("Proxy Xray Connectivity") and "IP:" in r.check_name and r.status == CheckStatus.PASS
        for r in results
    )

    if xray_domain_failed and xray_ip_passed:
        ip_str = server_ip or "IP"
        diagnostic.add_recommendation(f"🔒 Domain {server_domain} is blocked (DNS/SNI)")
        diagnostic.add_recommendation(f"Reason: cannot connect by domain, but works by IP ({ip_str})")
        diagnostic.add_recommendation(
            "Solutions:\n"
            "  1) Replace the domain with a new one in server configuration\n"
            "  2) Configure clients to connect by IP instead of domain\n"
            "  3) Use SNI obfuscation or selfsteal certificate"
        )

    # Xray connectivity failed (both domain and IP)
    xray_domain_failed = any(
        r.check_name.startswith("Proxy Xray Connectivity")
        and ("домен:" in r.check_name or "domain:" in r.check_name)
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
        diagnostic.add_recommendation(f"🚫 {ip_str} not responding — connection timeout")
        diagnostic.add_recommendation("Reason: server not responding by domain or IP — may be down or blocked")
        diagnostic.add_recommendation(
            "Solutions:\n  1) Check server availability and restart\n  2) Check Xray config (UUID, ports, certificates)"
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
    # Find a working proxy from passing diagnostics. Require non-empty results —
    # subscription section dividers / placeholders (e.g. "—— Gateways ——") get a
    # HostDiagnostic with no checks and thus default to PASS, but they aren't
    # real proxies and would produce nonsense "via <divider>" recommendations.
    passing = [
        d
        for d in all_diagnostics
        if d.overall_status == CheckStatus.PASS
        and d.results
        and any(
            r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS for r in d.results
        )
    ]

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
        socks_url = f"socks5://{xray.socks_user}:{xray.socks_password}@127.0.0.1:{socks_port}"

        # Test each problematic host by actually connecting to its server:port
        # through the working proxy's SOCKS tunnel. Previously this was probing a
        # generic status URL — which always succeeded as long as the working
        # proxy was working, producing bogus "reachable via X" claims for hosts
        # whose servers were genuinely down.
        async with aiohttp.ClientSession() as session:
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

                # Skip if target's server is the working proxy's server (any port) —
                # the answer is trivially "yes reachable" and only pollutes the report.
                if target_host == working_share.server:
                    continue

                target_protocol = "vless"
                for r in diag.results:
                    if r.check_name.startswith("Proxy Xray Connectivity") and "protocol" in r.details:
                        target_protocol = r.details.get("protocol", "vless")
                        break

                try:
                    cross_result = await check_xray_cross_connectivity(
                        target_host,
                        target_port,
                        target_protocol,
                        socks_url,
                        working_proxy_name=working_share.name,
                        working_proxy_protocol=working_share.protocol,
                        session=session,
                    )
                except Exception as e:
                    log.error(f"Cross-test failed for {target_host}:{target_port}: {e}")
                    continue

                diag.add_result(cross_result)

                if cross_result.status == CheckStatus.PASS:
                    diag.add_recommendation(
                        f"✓ {target_host}:{target_port} reachable via {working_share.name} "
                        f"— server is up; direct route may be RKN-blocked"
                    )
                elif cross_result.status == CheckStatus.WARN:
                    # TCP reachable, but service responded with 5xx on both paths
                    # → the Xray / backend service on this server is broken.
                    http_code = cross_result.details.get("http_status")
                    code_hint = f" (HTTP {http_code})" if http_code else ""
                    diag.add_recommendation(
                        f"⚠ {target_host}:{target_port} TCP reachable via {working_share.name}, "
                        f"but service returns an error{code_hint} — Xray backend on the server is broken"
                    )
                elif cross_result.status == CheckStatus.TIMEOUT:
                    diag.add_recommendation(
                        f"✗ {target_host}:{target_port} unreachable even via {working_share.name} "
                        f"— server is likely down / not running"
                    )
                else:
                    diag.add_recommendation(
                        f"✗ {target_host}:{target_port} cross-probe failed via {working_share.name} "
                        f"— {cross_result.message}"
                    )
    except Exception as e:
        log.error(f"Failed to start working proxy for cross-tests: {e}")
    finally:
        if xray_started:
            await xray.stop()
