"""Standalone analyzer for testing proxies from subscription without checker API."""

import asyncio
import re
import ssl
from collections.abc import Callable
from dataclasses import replace as dc_replace
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
from xray_analyzer.diagnostics.censor_checker import DomainStatus, run_censor_check
from xray_analyzer.diagnostics.dns_checker import check_dns_with_checkhost, close_dns_session, is_fakedns_ip
from xray_analyzer.diagnostics.dns_dpi_prober import DnsIntegrityReport, close_doh_session, probe_dns_integrity
from xray_analyzer.diagnostics.fat_probe_checker import check_fat_probe
from xray_analyzer.diagnostics.http_injection_probe import probe_http_injection
from xray_analyzer.diagnostics.proxy_cross_checker import check_xray_cross_connectivity
from xray_analyzer.diagnostics.proxy_ip_checker import check_proxy_exit_ip
from xray_analyzer.diagnostics.proxy_sni_checker import check_proxy_sni_connection
from xray_analyzer.diagnostics.proxy_tcp_checker import check_proxy_tcp_tunnel
from xray_analyzer.diagnostics.proxy_xray_checker import (
    XRAY_PROTOCOLS,
    run_xray_checks,
)
from xray_analyzer.diagnostics.sni_brute_force_checker import find_working_sni
from xray_analyzer.diagnostics.sni_brute_force_checker import to_diagnostic as sni_to_diagnostic
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL
from xray_analyzer.diagnostics.tcp_checker import check_tcp_connection
from xray_analyzer.diagnostics.tcp_ping_checker import check_tcp_ping
from xray_analyzer.diagnostics.telegram_checker import check_telegram
from xray_analyzer.diagnostics.telegram_checker import to_diagnostic as telegram_to_diagnostic
from xray_analyzer.diagnostics.tls_version_probe import probe_tls
from xray_analyzer.diagnostics.xray_manager import XrayInstance, launched_xray

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


def _is_ip_address(host: str) -> bool:
    """Return True if *host* is a valid IPv4 or IPv6 literal."""
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


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
        self._fat_probe: dict[tuple[str, int], asyncio.Task[DiagnosticResult]] = {}
        self._dns_integrity: dict[str, asyncio.Task[DnsIntegrityReport]] = {}
        self._tls_probe: dict[tuple[str, int], asyncio.Task[list[DiagnosticResult]]] = {}
        self._http_injection: dict[str, asyncio.Task[DiagnosticResult]] = {}

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

    def dns_integrity(self, host: str) -> asyncio.Task[DnsIntegrityReport]:
        task = self._dns_integrity.get(host)
        if task is None:
            task = asyncio.create_task(
                probe_dns_integrity([host], timeout=settings.dns_dpi_timeout),
                name=f"cached-dns-integrity:{host}",
            )
            self._dns_integrity[host] = task
        return task

    def fat_probe(self, host: str, port: int, sni: str | None = None) -> asyncio.Task[DiagnosticResult]:
        key = (host, port)
        task = self._fat_probe.get(key)
        if task is None:
            task = asyncio.create_task(
                check_fat_probe(
                    host,
                    port,
                    sni=sni or None,
                    iterations=settings.fat_probe_iterations,
                    chunk_size=settings.fat_probe_chunk_size,
                    connect_timeout=settings.fat_probe_connect_timeout,
                    read_timeout=settings.fat_probe_read_timeout,
                ),
                name=f"cached-fat-probe:{host}:{port}",
            )
            self._fat_probe[key] = task
        return task

    def tls_probe(self, host: str, port: int, stub_ips: set[str] | None = None) -> asyncio.Task[list[DiagnosticResult]]:
        key = (host, port)
        task = self._tls_probe.get(key)
        if task is None:

            async def _run() -> list[DiagnosticResult]:
                r12, r13 = await asyncio.gather(
                    probe_tls(host, forced_version=ssl.TLSVersion.TLSv1_2, port=port, stub_ips=stub_ips),
                    probe_tls(host, forced_version=ssl.TLSVersion.TLSv1_3, port=port, stub_ips=stub_ips),
                )
                return [r12, r13]

            task = asyncio.create_task(_run(), name=f"cached-tls-probe:{host}:{port}")
            self._tls_probe[key] = task
        return task

    def http_injection(self, host: str, stub_ips: set[str] | None = None) -> asyncio.Task[DiagnosticResult]:
        task = self._http_injection.get(host)
        if task is None:
            task = asyncio.create_task(
                probe_http_injection(host, stub_ips=stub_ips),
                name=f"cached-http-injection:{host}",
            )
            self._http_injection[host] = task
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
        share_by_label = {f"{s.name.strip()} ({s.server}:{s.port})": s for s in shares}

        # One shared probe cache for the whole run — see _DirectProbeCache docstring.
        probe_cache = _DirectProbeCache()

        async def _wrapped(share: ProxyShareURL) -> HostDiagnostic:
            try:
                return await asyncio.wait_for(
                    analyze_single_proxy(share, probe_cache=probe_cache),
                    timeout=settings.analyze_proxy_timeout,
                )
            except TimeoutError:
                label = f"{share.name.strip()} ({share.server}:{share.port})"
                diag = HostDiagnostic(host=label)
                diag.add_result(
                    DiagnosticResult(
                        check_name="Analysis Timeout",
                        status=CheckStatus.TIMEOUT,
                        severity=CheckSeverity.CRITICAL,
                        message=f"Analysis exceeded {settings.analyze_proxy_timeout}s limit",
                        details={"timeout_seconds": settings.analyze_proxy_timeout},
                    )
                )
                return diag

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
        # The DNS/DoH checks use shared aiohttp sessions — close to avoid leaks.
        await close_dns_session()
        await close_doh_session()


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
    name = share.name.strip()
    label = f"{name} ({host}:{port})"

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

    # A4. DNS Integrity (UDP vs DoH cross-check) — only for domain-based servers
    _host_is_domain = not _is_ip_address(host)
    _stub_ips: set[str] | None = None
    if _host_is_domain and settings.dns_dpi_enabled:
        try:
            dns_integrity_report = await cache.dns_integrity(host)
            for result in dns_integrity_report.results:
                diagnostic.add_result(result)
            _stub_ips = dns_integrity_report.stub_ips or None
        except Exception as e:
            log.warning(f"DNS integrity probe failed for {host}: {e}")
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="DNS Integrity",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message=f"DNS integrity probe error: {e}",
                    details={"error": str(e)},
                )
            )

    # A5. Fat Probe (RKN 16-20 KB DPI throttle detection)
    if tcp_result.status == CheckStatus.PASS and settings.rkn_throttle_check_enabled:
        fat_probe_result = await cache.fat_probe(host, port, sni=share.sni)
        diagnostic.add_result(fat_probe_result)

    # A6. TLS Version Split (TLS 1.2 vs 1.3 asymmetry)
    if tcp_result.status == CheckStatus.PASS and settings.analyze_tls_probe_enabled:
        try:
            tls_results = await cache.tls_probe(host, port, stub_ips=_stub_ips)
            for result in tls_results:
                diagnostic.add_result(result)
        except Exception as e:
            log.warning(f"TLS version probe failed for {host}: {e}")
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="TLS 1.2 / 1.3 Probe",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message=f"TLS probe error: {e}",
                    details={"error": str(e)},
                )
            )

    # A7. HTTP Injection (port 80 ISP redirect/block page detection)
    if _host_is_domain and settings.analyze_http_injection_enabled:
        try:
            http_inj_result = await cache.http_injection(host, stub_ips=_stub_ips)
            diagnostic.add_result(http_inj_result)
        except Exception as e:
            log.warning(f"HTTP injection probe failed for {host}: {e}")
            diagnostic.add_result(
                DiagnosticResult(
                    check_name="HTTP Injection Probe",
                    status=CheckStatus.SKIP,
                    severity=CheckSeverity.INFO,
                    message=f"HTTP injection probe error: {e}",
                    details={"error": str(e)},
                )
            )

    # 4. Protocol-specific tests
    if share.protocol.lower() in XRAY_PROTOCOLS:
        # VLESS/Trojan/SS — test via Xray with lifecycle managed here
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
                # Filter out FakeDNS virtual IPs — connecting to 198.18.x.x makes no sense
                real_ips = [ip for ip in local_ips if not is_fakedns_ip(ip)]
                fallback_ip = real_ips[0] if real_ips else None

            await _run_xray_phase(diagnostic, share, fallback_ip)
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

    # C1. SNI Brute-Force — only when fat probe detected DPI throttle AND proxy works
    if settings.analyze_sni_brute_enabled:
        fat_probe_throttled = any(
            r.check_name == "TCP 16-20 KB Fat Probe" and r.details.get("label") == "tcp_16_20"
            for r in diagnostic.results
        )
        proxy_works = any(
            r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS
            for r in diagnostic.results
        )
        if fat_probe_throttled and proxy_works:
            try:
                # Use RTT from fat probe as hint for faster probing
                fat_rtt = None
                for r in diagnostic.results:
                    if r.check_name == "TCP 16-20 KB Fat Probe":
                        fat_rtt = r.details.get("rtt_ms")
                        break

                sni_result = await find_working_sni(
                    host,
                    port,
                    max_candidates=settings.sni_brute_max_candidates,
                    hint_rtt_ms=fat_rtt,
                )
                diagnostic.add_result(sni_to_diagnostic(sni_result))
            except Exception as e:
                log.warning(f"SNI brute-force failed for {host}:{port}: {e}")

    # Add smart recommendations based on test results
    _add_standalone_recommendations(diagnostic, share)

    # Re-evaluate overall status using authoritative signals (proxy works → not FAIL)
    diagnostic.finalize_status()

    return diagnostic


async def _run_xray_phase(
    diagnostic: HostDiagnostic,
    share: ProxyShareURL,
    fallback_ip: str | None,
) -> None:
    """Run Phase B: Xray-dependent checks with lifecycle managed here.

    Starts Xray, runs connectivity + Exit IP + SNI. If domain connectivity
    fails and a fallback IP is available, starts a *separate* Xray instance
    with the IP-based config and retests.

    The socks_url is available for future Phase B extensions (censorship
    canary, Telegram, etc.) — they will be added inside the ``if
    connectivity_passed`` block.
    """
    try:
        async with launched_xray(share) as socks_url, aiohttp.ClientSession() as session:
            # B1-B2: Connectivity + Exit IP + SNI
            xray_results = await run_xray_checks(
                share,
                socks_url,
                session,
                label_suffix=f" (домен: {share.server})",
            )
            for result in xray_results:
                diagnostic.add_result(result)

            connectivity_passed = any(
                r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS
                for r in xray_results
            )

            if connectivity_passed:
                # B3: Censorship canary — test blocked domains through proxy
                if settings.analyze_censor_canary_enabled:
                    canary_result = await _run_censor_canary(socks_url, share)
                    diagnostic.add_result(canary_result)

                # B4: Telegram reachability through proxy
                if settings.analyze_telegram_enabled:
                    tg_result = await _run_telegram_check(socks_url, share)
                    diagnostic.add_result(tg_result)

    except RuntimeError as e:
        log.error(f"Failed to start Xray for {share.name}: {e}")
        diagnostic.add_result(
            DiagnosticResult(
                check_name=f"Proxy Xray Connectivity (домен: {share.server})",
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
                ],
            )
        )
        return

    # IP fallback: if domain connectivity failed and we have a resolved IP,
    # start a NEW Xray instance with the IP-based share (different config).
    connectivity_passed = any(
        r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS for r in diagnostic.results
    )

    if connectivity_passed or not fallback_ip:
        return

    log.info(f"Domain test failed for {share.server}, trying fallback IP: {fallback_ip}")
    ip_share = dc_replace(share, server=fallback_ip)
    try:
        async with launched_xray(ip_share) as ip_socks_url, aiohttp.ClientSession() as session:
            ip_results = await run_xray_checks(
                ip_share,
                ip_socks_url,
                session,
                label_suffix=f" (IP: {fallback_ip})",
            )

            ip_connectivity = next(
                (r for r in ip_results if r.check_name.startswith("Proxy Xray Connectivity")),
                None,
            )

            if ip_connectivity and ip_connectivity.status == CheckStatus.PASS:
                # Domain failed but IP works — add a summary result and the
                # passing IP results (exit IP, SNI).
                diagnostic.add_result(
                    DiagnosticResult(
                        check_name="Proxy Xray Connectivity",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.WARNING,
                        message=(
                            f"Domain {share.server} did not respond, but IP {fallback_ip} works "
                            f"(likely DNS / geo-blocking). Proxy is usable via IP."
                        ),
                        details={
                            "domain": share.server,
                            "fallback_ip": fallback_ip,
                            "http_status": ip_connectivity.details.get("http_status"),
                        },
                    )
                )
                # Add non-connectivity results from IP test (exit IP, SNI)
                for r in ip_results:
                    if not r.check_name.startswith("Proxy Xray Connectivity"):
                        diagnostic.add_result(r)
            else:
                # Both domain and IP failed — add IP results too
                for r in ip_results:
                    diagnostic.add_result(r)

    except RuntimeError as e:
        log.error(f"Failed to start Xray for IP fallback {fallback_ip}: {e}")


# Default canary domains — a small representative set of commonly blocked sites.
CANARY_DOMAINS = [
    "youtube.com",
    "instagram.com",
    "x.com",
    "api.telegram.org",
    "discord.com",
]


async def _run_censor_canary(socks_url: str, share: ProxyShareURL) -> DiagnosticResult:
    """Run a small censorship canary check through the proxy tunnel.

    Tests a handful of commonly blocked domains and returns a single aggregate
    DiagnosticResult summarizing how many are reachable.
    """
    canary_raw = settings.analyze_canary_domains.strip()
    domains = [d.strip() for d in canary_raw.split(",") if d.strip()] if canary_raw else CANARY_DOMAINS

    try:
        summary = await run_censor_check(
            domains=domains,
            proxy_url=socks_url,
            timeout=settings.censor_check_timeout,
            max_parallel=5,
        )

        blocked_names = [r.domain for r in summary.results if r.status == DomainStatus.BLOCKED]
        partial_names = [r.domain for r in summary.results if r.status == DomainStatus.PARTIAL]
        ok_count = summary.ok

        if summary.blocked == 0 and summary.partial == 0:
            return DiagnosticResult(
                check_name="Censor Canary",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"All {ok_count} canary domains reachable",
                details={
                    "domains_checked": len(domains),
                    "ok": ok_count,
                    "blocked": 0,
                    "partial": 0,
                    "proxy": share.name,
                },
            )
        elif summary.blocked > 0:
            return DiagnosticResult(
                check_name="Censor Canary",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.WARNING,
                message=f"{summary.blocked} blocked, {summary.partial} partial of {len(domains)} canary domains",
                details={
                    "domains_checked": len(domains),
                    "ok": ok_count,
                    "blocked": summary.blocked,
                    "blocked_count": summary.blocked,
                    "blocked_domains": blocked_names,
                    "partial": summary.partial,
                    "partial_domains": partial_names,
                    "proxy": share.name,
                },
            )
        else:
            return DiagnosticResult(
                check_name="Censor Canary",
                status=CheckStatus.WARN,
                severity=CheckSeverity.WARNING,
                message=f"{summary.partial} partially blocked of {len(domains)} canary domains",
                details={
                    "domains_checked": len(domains),
                    "ok": ok_count,
                    "blocked": 0,
                    "partial": summary.partial,
                    "partial_domains": partial_names,
                    "proxy": share.name,
                },
            )
    except Exception as e:
        return DiagnosticResult(
            check_name="Censor Canary",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Canary check failed: {e}",
            details={"proxy": share.name, "error": str(e)},
        )


async def _run_telegram_check(socks_url: str, share: ProxyShareURL) -> DiagnosticResult:
    """Run Telegram reachability check through the proxy tunnel."""
    try:
        report = await check_telegram(
            proxy=socks_url,
            stall_timeout=settings.telegram_stall_timeout,
            total_timeout=settings.telegram_total_timeout,
        )
        result = telegram_to_diagnostic(report)
        # Override check name to distinguish from direct Telegram checks
        result = result.model_copy(
            update={
                "check_name": "Telegram Reachability",
                "details": {**result.details, "proxy": share.name, "via_proxy": True},
            }
        )
        return result
    except Exception as e:
        return DiagnosticResult(
            check_name="Telegram Reachability",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Telegram check failed: {e}",
            details={"proxy": share.name, "error": str(e)},
        )


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

    # DNS mismatch with Check-Host — only flag when proxy connectivity also fails.
    # CDN/Anycast naturally return different IPs per region; mismatches alone are
    # not evidence of geo-blocking unless the proxy path itself is broken.
    dns_mismatch = next(
        (
            r
            for r in results
            if r.check_name.startswith("DNS Resolution")
            and r.details.get("ip_match") is False
            and not r.details.get("fakedns_ips")
        ),
        None,
    )
    xray_connectivity_failed = not any(
        r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS for r in results
    )
    if dns_mismatch and xray_connectivity_failed:
        diagnostic.add_recommendation(
            f"⚠️ DNS for {server_domain} differs from Check-Host and proxy is unreachable — possible DNS poisoning"
        )
        diagnostic.add_recommendation("Try connecting by IP or using DoH/DoT to bypass DNS manipulation")

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

    # --- New check recommendations ---

    # Fat Probe: DPI throttle detected
    fat_probe_result = next(
        (r for r in results if r.check_name == "TCP 16-20 KB Fat Probe" and r.details.get("label") == "tcp_16_20"),
        None,
    )
    if fat_probe_result:
        drop_kb = fat_probe_result.details.get("drop_at_kb", "?")
        diagnostic.add_recommendation(
            f"DPI throttle detected on {server_domain}:{share.port} — connection dropped at ~{drop_kb} KB"
        )
        diagnostic.add_recommendation("ISP drops encrypted connections in the 16-20 KB window (TSPU signature)")
        # Check if SNI brute found a workaround
        sni_result = next(
            (r for r in results if r.check_name == "SNI Brute Force" and r.status == CheckStatus.PASS), None
        )
        if sni_result:
            working_sni = sni_result.details.get("first_working", "")
            if working_sni:
                diagnostic.add_recommendation(
                    f"Working SNI found: {working_sni} — configure REALITY serverName to this value"
                )
        else:
            diagnostic.add_recommendation("Use REALITY/XTLS-Vision or try --sni-brute to find a bypass SNI")

    # DNS Integrity: spoofed/intercepted DNS
    dns_integrity_issues = [
        r
        for r in results
        if r.check_name.startswith("DNS Integrity") and r.status in (CheckStatus.FAIL, CheckStatus.WARN)
    ]
    for r in dns_integrity_issues:
        verdict = r.details.get("verdict", "")
        if verdict in ("spoof", "intercept", "fake_nxdomain", "fake_empty"):
            diagnostic.add_recommendation(
                f"DNS tampering ({verdict}) detected for {server_domain} — ISP manipulates DNS responses"
            )
            diagnostic.add_recommendation("Use DoH/DoT or connect by IP to bypass DNS manipulation")
            break

    # TLS Version asymmetry
    tls_12 = next((r for r in results if "TLS 1.2" in r.check_name), None)
    tls_13 = next((r for r in results if "TLS 1.3" in r.check_name), None)
    if tls_12 and tls_13:
        if tls_12.status == CheckStatus.PASS and tls_13.status != CheckStatus.PASS:
            diagnostic.add_recommendation(
                f"TLS asymmetry on {server_domain}: TLS 1.2 works, TLS 1.3 blocked — force TLS 1.2"
            )
        elif tls_13.status == CheckStatus.PASS and tls_12.status != CheckStatus.PASS:
            diagnostic.add_recommendation(
                f"TLS asymmetry on {server_domain}: TLS 1.3 works, TLS 1.2 blocked — force TLS 1.3"
            )

    # HTTP Injection detected
    http_inj = next(
        (r for r in results if r.check_name.startswith("HTTP Injection") and r.status == CheckStatus.FAIL), None
    )
    if http_inj:
        diagnostic.add_recommendation(
            f"ISP HTTP injection detected on port 80 for {server_domain} — DPI is active on this path"
        )

    # Censor Canary: proxy can't unblock sites
    canary_fail = next((r for r in results if r.check_name == "Censor Canary" and r.status == CheckStatus.FAIL), None)
    if canary_fail:
        blocked_domains = canary_fail.details.get("blocked_domains", [])
        blocked_str = ", ".join(blocked_domains[:3])
        if len(blocked_domains) > 3:
            blocked_str += f" +{len(blocked_domains) - 3} more"
        diagnostic.add_recommendation(
            f"Proxy cannot reach {canary_fail.details.get('blocked_count', '?')} blocked sites: {blocked_str}"
        )
        diagnostic.add_recommendation(
            "Exit node may be censored, or server DNS is poisoned — check resolv.conf on the server"
        )

    # Telegram: blocked or slow through proxy
    tg_result = next(
        (r for r in results if r.check_name == "Telegram Reachability" and r.status != CheckStatus.PASS), None
    )
    if tg_result:
        verdict = tg_result.details.get("verdict", "")
        if verdict == "blocked":
            diagnostic.add_recommendation("Telegram completely blocked through this proxy's exit network")
        elif verdict in ("slow", "stalled"):
            diagnostic.add_recommendation("Telegram DL/UL throttled through this proxy — exit ISP may be throttling")


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
        and any(r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS for r in d.results)
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
            sem = asyncio.Semaphore(5)

            async def _cross_test_one(diag: HostDiagnostic) -> None:
                host = diag.host
                start = host.rfind("(")
                end = host.rfind(")")
                if start == -1 or end == -1:
                    return
                server_port = host[start + 1 : end]
                parts = server_port.rsplit(":", 1)
                if len(parts) != 2:
                    return
                target_host, target_port_str = parts
                try:
                    target_port = int(target_port_str)
                except ValueError:
                    return

                if target_host == working_share.server:
                    return

                target_protocol = "vless"
                for r in diag.results:
                    if r.check_name.startswith("Proxy Xray Connectivity") and "protocol" in r.details:
                        target_protocol = r.details.get("protocol", "vless")
                        break

                async with sem:
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
                        return

                diag.add_result(cross_result)

                if cross_result.status == CheckStatus.PASS:
                    diag.add_recommendation(
                        f"✓ {target_host}:{target_port} reachable via {working_share.name} "
                        f"— server is up; direct route may be RKN-blocked"
                    )
                elif cross_result.status == CheckStatus.WARN:
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

            await asyncio.gather(*[_cross_test_one(d) for d in problematic])

        # Cross-proxy TIMEOUT results push overall_status back to FAIL via
        # add_result, but finalize_status was already called before cross-tests.
        # Re-finalize so that hosts where the proxy itself works (Proxy Xray
        # Connectivity passed) stay at WARN, not FAIL.
        for diag in problematic:
            diag.finalize_status()
    except Exception as e:
        log.error(f"Failed to start working proxy for cross-tests: {e}")
    finally:
        if xray_started:
            await xray.stop()
