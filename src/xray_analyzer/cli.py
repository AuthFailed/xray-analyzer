"""CLI interface for xray-analyzer using argparse and rich."""

import argparse
import asyncio
import contextlib
import json
import re
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from xray_analyzer import cli_dpi
from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger, setup_logging
from xray_analyzer.core.models import CheckStatus, DiagnosticResult, HostDiagnostic
from xray_analyzer.core.standalone_analyzer import _is_valid_server_address, analyze_subscription_proxies
from xray_analyzer.diagnostics.cdn_target_scanner import load_targets, scan_targets
from xray_analyzer.diagnostics.censor_checker import (
    ALLOW_DOMAINS_LISTS,
    DEFAULT_CENSOR_DOMAINS,
    DomainCheckResult,
    DomainStatus,
    check_domain_verbose,
    fetch_allow_domains_list,
    fetch_whitelist_domains,
    run_censor_check,
)
from xray_analyzer.diagnostics.dns_dpi_prober import probe_dns_integrity
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL, fetch_subscription, parse_share_url
from xray_analyzer.diagnostics.telegram_checker import check_telegram
from xray_analyzer.diagnostics.xray_downloader import ensure_xray
from xray_analyzer.diagnostics.xray_manager import XrayInstance
from xray_analyzer.metrics.server import MetricsState, ProxyAnalysisMetricsState, run_metrics_server

log = get_logger("cli")
console = Console()
error_console = Console(stderr=True)

_XRAY_SHARE_SCHEMES = {"vless", "trojan", "ss"}


@asynccontextmanager
async def _xray_proxy_context(proxy_url: str | None, silent: bool = False) -> AsyncIterator[str | None]:
    """
    If proxy_url is a VLESS/Trojan/SS share link, start an Xray instance and yield
    the local socks5:// URL. Otherwise yield proxy_url unchanged.
    """
    if proxy_url:
        scheme = proxy_url.split("://", 1)[0].lower()
        if scheme in _XRAY_SHARE_SCHEMES:
            share = parse_share_url(proxy_url)
            if share is None:
                raise ValueError(f"Cannot parse proxy share URL: {proxy_url}")

            xray_path = await ensure_xray(settings.xray_binary_path)
            if not xray_path:
                raise RuntimeError("Xray binary not found — cannot use VLESS/Trojan/SS proxy")
            settings.xray_binary_path = xray_path

            xray = XrayInstance(share)
            try:
                socks_port = await xray.start()
                if not silent:
                    label = share.name or f"{share.server}:{share.port}"
                    console.print(
                        f"[green]✓[/green] Xray started: [bold]{label}[/bold] → [dim]socks5://127.0.0.1:{socks_port}[/dim]"
                    )
                yield f"socks5://{xray.socks_user}:{xray.socks_password}@127.0.0.1:{socks_port}"
            finally:
                await xray.stop()
            return

    yield proxy_url


_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def load_domains_file(path: str) -> list[str]:
    """
    Read a file with one domain per line, validate each entry, and return valid domains.

    Prints a warning table for invalid lines. Raises SystemExit if the file cannot be read.
    """
    file = Path(path)
    try:
        raw_lines = file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        error_console.print(f"[bold red]✗[/bold red] Cannot read file '{path}': {exc}")
        sys.exit(1)

    valid: list[str] = []
    invalid: list[tuple[int, str]] = []

    for lineno, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue  # skip blank lines and comments
        if _DOMAIN_RE.match(stripped):
            valid.append(stripped)
        else:
            invalid.append((lineno, stripped))

    if invalid:
        console.print(f"\n[bold yellow]⚠  {len(invalid)} invalid line(s) in '{path}':[/bold yellow]")
        for lineno, raw in invalid:
            console.print(f"  [dim]line {lineno:>4}:[/dim] [red]{raw}[/red]")
        console.print()

    if not valid:
        error_console.print(f"[bold red]✗[/bold red] No valid domains found in '{path}'")
        sys.exit(1)

    console.print(
        f"[green]✓[/green] Loaded [bold]{len(valid)}[/bold] valid domain(s) from [cyan]{path}[/cyan]"
        + (f"  [dim]({len(invalid)} skipped)[/dim]" if invalid else "")
    )
    return valid


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="xray-analyzer",
        description="Advanced diagnostics tool for Xray proxy servers",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Run full analysis on all proxies")
    analyze_parser.add_argument(
        "proxies",
        nargs="*",
        help="Proxy share links to analyze (vless://..., trojan://..., ss://...)",
    )
    analyze_parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously monitor proxies at configured interval",
    )
    analyze_parser.add_argument(
        "--subscription-url",
        type=str,
        help="Subscription URL with VLESS/Trojan/SS share links (overrides SUBSCRIPTION_URL)",
    )
    analyze_parser.add_argument(
        "--subscription-hwid",
        type=str,
        help="HWID header for subscription (overrides SUBSCRIPTION_HWID)",
    )
    analyze_parser.add_argument(
        "--no-xray",
        action="store_true",
        help="Disable Xray-based proxy testing (overrides XRAY_TEST_ENABLED)",
    )
    analyze_parser.add_argument(
        "--no-rkn-throttle",
        action="store_true",
        help="Disable RKN DPI throttle detection (overrides RKN_THROTTLE_CHECK_ENABLED)",
    )
    analyze_parser.add_argument(
        "--no-sni",
        action="store_true",
        help="Disable SNI connection test (overrides PROXY_SNI_TEST_ENABLED)",
    )
    analyze_parser.add_argument(
        "--check-host-api-key",
        type=str,
        help="API key for Check-Host.net (overrides CHECK_HOST_API_KEY)",
    )
    analyze_parser.add_argument(
        "--proxy-status-url",
        type=str,
        help="URL for proxy status verification (overrides PROXY_STATUS_CHECK_URL)",
    )
    analyze_parser.add_argument(
        "--proxy-ip-url",
        type=str,
        help="URL for exit IP verification (overrides PROXY_IP_CHECK_URL)",
    )
    analyze_parser.add_argument(
        "--sni-domain",
        type=str,
        help="Domain for SNI testing (overrides PROXY_SNI_DOMAIN)",
    )
    analyze_parser.add_argument(
        "--interval",
        type=int,
        help="Check interval in seconds for --watch mode (overrides CHECK_INTERVAL_SECONDS)",
    )
    analyze_parser.add_argument(
        "--no-dpi",
        action="store_true",
        help="Disable all direct DPI probes (fat-probe, TLS split, HTTP injection)",
    )
    analyze_parser.add_argument(
        "--censor-canary",
        action="store_true",
        help="Enable censorship canary check through each proxy",
    )
    analyze_parser.add_argument(
        "--telegram",
        action="store_true",
        help="Enable Telegram reachability check through each proxy",
    )
    analyze_parser.add_argument(
        "--sni-brute",
        action="store_true",
        help="Enable SNI brute-force when DPI throttle is detected",
    )
    analyze_parser.add_argument(
        "--full",
        action="store_true",
        help="Enable all optional checks (DPI probes, censor canary, Telegram, SNI brute)",
    )
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON (machine-readable)",
    )
    analyze_parser.add_argument(
        "--only-failed",
        action="store_true",
        help="Only show hosts with problems",
    )
    analyze_parser.add_argument(
        "--only-passed",
        action="store_true",
        help="Only show hosts without problems",
    )
    analyze_parser.add_argument(
        "--serve",
        action="store_true",
        help="Start a Prometheus metrics server and loop analysis (implies --watch)",
    )
    analyze_parser.add_argument(
        "--port",
        type=int,
        help="Metrics server port for --serve mode (default: METRICS_PORT or 9090)",
    )
    analyze_parser.add_argument(
        "--host",
        type=str,
        help="Metrics server bind host for --serve mode (default: METRICS_HOST or 0.0.0.0)",
    )

    # check command — single domain step-by-step diagnosis
    check_parser = subparsers.add_parser(
        "check",
        help="Diagnose a single domain: DNS, TCP, ping, TLS, HTTP, DPI — step by step",
    )
    check_parser.add_argument("domain", help="Domain or IP to diagnose (e.g. meduza.io, 1.2.3.4)")
    check_parser.add_argument("--port", type=int, default=443, help="Port to check (default: 443)")
    check_parser.add_argument(
        "--proxy",
        help="Route checks through this proxy (e.g., socks5://127.0.0.1:1080)",
    )
    check_parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout per check in seconds (default: from config)",
    )
    check_parser.add_argument(
        "--subscription",
        metavar="URL",
        help="Test domain through all proxies from this subscription URL",
    )

    # scan command — bulk censorship scan across many domains
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan domains for censorship/blocking (bulk, parallel, with progress bar)",
    )
    scan_parser.add_argument(
        "domains",
        nargs="*",
        help="Domains to scan (default: built-in list of commonly blocked sites)",
    )
    _allow_domains_choices = list(ALLOW_DOMAINS_LISTS.keys())
    scan_parser.add_argument(
        "--list",
        choices=["default", "whitelist", *_allow_domains_choices],
        default="default",
        help=(
            "Predefined domain list to scan. Options:\n"
            "  default        — built-in list of commonly blocked sites\n"
            "  whitelist      — Russia mobile internet whitelist (hxehex/russia-mobile-internet-whitelist)\n"
            + "".join(f"  {name:<14} — {desc}\n" for name, (_, desc) in ALLOW_DOMAINS_LISTS.items())
            + "(itdoginfo/allow-domains lists are downloaded on demand)"
        ),
    )
    scan_parser.add_argument(
        "--file",
        metavar="PATH",
        help="Path to a text file with one domain per line (validated before scanning)",
    )
    scan_parser.add_argument(
        "--proxy",
        help="Route HTTP checks through this proxy (e.g., socks5://127.0.0.1:1080)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout per domain in seconds (default: from config)",
    )
    scan_parser.add_argument(
        "--max-parallel",
        type=int,
        help="Maximum parallel checks (default: from config)",
    )

    # serve command — metrics daemon
    serve_parser = subparsers.add_parser(
        "serve",
        help="Run periodic censorship scans and expose results as Prometheus /metrics",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        help=f"Metrics server port (default: {settings.metrics_port}, env: METRICS_PORT)",
    )
    serve_parser.add_argument(
        "--host",
        type=str,
        help=f"Metrics server bind host (default: {settings.metrics_host}, env: METRICS_HOST)",
    )
    serve_parser.add_argument(
        "--interval",
        type=int,
        help="Seconds between scans (default: CHECK_INTERVAL_SECONDS from config)",
    )
    serve_parser.add_argument(
        "domains",
        nargs="*",
        help="Domains to scan (default: built-in list of commonly blocked sites)",
    )
    serve_parser.add_argument(
        "--list",
        choices=["default", "whitelist", *_allow_domains_choices],
        default="default",
        help="Predefined domain list to scan (same choices as the scan command)",
    )
    serve_parser.add_argument(
        "--file",
        metavar="PATH",
        help="Path to a text file with one domain per line (validated before scanning)",
    )
    serve_parser.add_argument(
        "--proxy",
        help="Route checks through this proxy (e.g., socks5://127.0.0.1:1080)",
    )
    serve_parser.add_argument(
        "--subscription",
        metavar="URL",
        help="Check domains through every proxy in this subscription URL (VLESS/Trojan/SS); exposes per-proxy metrics",
    )
    serve_parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout per domain in seconds (default: CENSOR_CHECK_TIMEOUT from config)",
    )
    serve_parser.add_argument(
        "--max-parallel",
        type=int,
        help="Maximum parallel domain checks (default: CENSOR_CHECK_MAX_PARALLEL from config)",
    )

    # dpi subcommand group — lives in cli_dpi.py to keep this file focused
    cli_dpi.register(subparsers)

    return parser


async def cmd_analyze(args: argparse.Namespace) -> int:
    """Run full analysis command."""
    # Apply CLI overrides to settings
    if getattr(args, "no_xray", False):
        settings.xray_test_enabled = False
    if getattr(args, "no_rkn_throttle", False):
        settings.rkn_throttle_check_enabled = False
    if getattr(args, "no_sni", False):
        settings.proxy_sni_test_enabled = False
    if getattr(args, "check_host_api_key", None):
        settings.check_host_api_key = args.check_host_api_key
    if getattr(args, "proxy_status_url", None):
        settings.proxy_status_check_url = args.proxy_status_url
    if getattr(args, "proxy_ip_url", None):
        settings.proxy_ip_check_url = args.proxy_ip_url
    if getattr(args, "sni_domain", None):
        settings.proxy_sni_domain = args.sni_domain
    if getattr(args, "interval", None):
        settings.check_interval_seconds = args.interval
    if getattr(args, "subscription_url", None):
        settings.subscription_url = args.subscription_url
    if getattr(args, "subscription_hwid", None):
        settings.subscription_hwid = args.subscription_hwid
    if getattr(args, "no_dpi", False):
        settings.rkn_throttle_check_enabled = False
        settings.analyze_tls_probe_enabled = False
        settings.analyze_http_injection_enabled = False
    if getattr(args, "full", False):
        settings.analyze_tls_probe_enabled = True
        settings.analyze_http_injection_enabled = True
        settings.analyze_censor_canary_enabled = True
        settings.analyze_telegram_enabled = True
        settings.analyze_sni_brute_enabled = True
    # Explicit flags override --full / --no-dpi
    if getattr(args, "censor_canary", False):
        settings.analyze_censor_canary_enabled = True
    if getattr(args, "telegram", False):
        settings.analyze_telegram_enabled = True
    if getattr(args, "sni_brute", False):
        settings.analyze_sni_brute_enabled = True

    # Collect proxy shares from all sources
    proxy_links: list[str] = getattr(args, "proxies", None) or []

    return await _run_standalone_analysis(
        proxy_links=proxy_links,
        json_output=getattr(args, "json_output", False),
        only_failed=getattr(args, "only_failed", False),
        only_passed=getattr(args, "only_passed", False),
        serve=getattr(args, "serve", False) or getattr(args, "watch", False),
        serve_host=getattr(args, "host", None),
        serve_port=getattr(args, "port", None),
    )


async def _run_standalone_analysis(
    proxy_links: list[str] | None = None,
    json_output: bool = False,
    only_failed: bool = False,
    only_passed: bool = False,
    serve: bool = False,
    serve_host: str | None = None,
    serve_port: int | None = None,
) -> int:
    """Run analysis using subscription URL and/or direct proxy links."""
    try:
        # Ensure Xray is available if testing VLESS/Trojan/SS
        if settings.xray_test_enabled:
            with console.status("[dim]Checking Xray binary...[/dim]", spinner="dots"):
                xray_path = await ensure_xray(settings.xray_binary_path)
            if xray_path:
                settings.xray_binary_path = xray_path
                console.print(f"[green]✓[/green] Xray ready: [dim]{xray_path}[/dim]")
            else:
                console.print("[yellow]⚠[/yellow] Xray not found — VLESS/Trojan/SS tests will be skipped")
                settings.xray_test_enabled = False

        # Collect shares from all sources
        shares: list[ProxyShareURL] = []

        # 1. Direct proxy links from CLI args
        if proxy_links:
            for link in proxy_links:
                parsed = parse_share_url(link)
                if parsed:
                    shares.append(parsed)
                else:
                    error_console.print(f"[yellow]⚠[/yellow] Cannot parse proxy link: [dim]{link}[/dim]")
            if shares:
                console.print(f"[green]✓[/green] Parsed [bold]{len(shares)}[/bold] proxy link(s) from arguments")

        # 2. Subscription URL
        if settings.subscription_url:
            with console.status("[dim]Fetching subscription...[/dim]", spinner="dots"):
                sub_shares = await fetch_subscription(
                    settings.subscription_url,
                    hwid=settings.subscription_hwid,
                )
            console.print(f"[green]✓[/green] Loaded [bold]{len(sub_shares)}[/bold] proxies from subscription")
            shares.extend(sub_shares)

        if not shares:
            error_console.print(
                "[bold red]No proxies to analyze.[/bold red]\n"
                "Provide proxy links as arguments or set --subscription-url / SUBSCRIPTION_URL.\n"
                "Examples:\n"
                "  xray-analyzer analyze vless://uuid@server:443?...\n"
                "  xray-analyzer analyze --subscription-url https://sub.example.com/link"
            )
            return 1

        async def _run_once() -> list[HostDiagnostic]:
            # Start panel + live progress bar
            source_label = "subscription" if settings.subscription_url else "CLI"
            console.print()
            console.print(
                Panel(
                    f"[bold cyan]Proxy Analysis[/bold cyan]\n"
                    f"[dim]{source_label} · {len(shares)} proxies · Xray "
                    f"{'enabled' if settings.xray_test_enabled else 'disabled'}[/dim]",
                    border_style="blue",
                    padding=(0, 2),
                )
            )
            console.print()

            # Pre-compute max host column width for aligned progress output.
            max_host_w = 0
            for s in shares:
                label = f"{s.name.strip()} ({s.server}:{s.port})"
                host_part = f"[bold]{label}[/bold] [dim]({s.protocol})[/dim]"
                max_host_w = max(max_host_w, Text.from_markup(host_part).cell_len)

            with Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=28),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                task_id = progress.add_task(f"[cyan]Analyzing {len(shares)} proxies[/cyan]", total=len(shares))

                def on_proxy_complete(diag: HostDiagnostic, share: ProxyShareURL) -> None:
                    if not diag.results:
                        # Skipped virtual/invalid host — advance silently
                        progress.advance(task_id)
                        return
                    _print_proxy_progress_line(progress, diag, share.protocol, max_host_w)
                    progress.advance(task_id)

                def on_phase(phase: str, count: int) -> None:
                    if phase == "cross_proxy":
                        progress.update(
                            task_id,
                            description=f"[cyan]Cross-checking {count} problem hosts via a working proxy...[/cyan]",
                        )
                    elif phase == "finalizing":
                        progress.update(task_id, description="[cyan]Finalizing report...[/cyan]")

                return await analyze_subscription_proxies(
                    shares,
                    on_proxy_complete=on_proxy_complete,
                    on_phase=on_phase,
                )

        if serve:
            # --serve mode: start metrics HTTP server and loop analysis
            host = serve_host or settings.metrics_host
            port = serve_port or settings.metrics_port
            interval = settings.check_interval_seconds

            state = ProxyAnalysisMetricsState()
            # Build label → share map (same format as standalone_analyzer.py)
            share_by_label: dict[str, ProxyShareURL] = {}
            for s in shares:
                label = f"{s.name.strip()} ({s.server}:{s.port})"
                state.register_proxy(label, s)
                share_by_label[label] = s

            console.print()
            console.print(
                Panel(
                    f"[bold cyan]Proxy Analysis Metrics[/bold cyan]\n"
                    f"[green]http://{host}:{port}/metrics[/green]\n"
                    f"[dim]{len(shares)} proxies · analyze every {interval}s[/dim]",
                    border_style="blue",
                    padding=(0, 2),
                )
            )
            console.print()

            runner = await run_metrics_server(host, port, state)
            console.print(
                f"[green]✓[/green] Listening on [bold]http://{host}:{port}/metrics[/bold]  (Ctrl+C to stop)\n"
            )

            try:
                while True:
                    cycle_t0 = time.monotonic()
                    try:
                        diagnostics = await _run_once()
                        duration = time.monotonic() - cycle_t0

                        for diag in diagnostics:
                            state.update_proxy(diag.host, diag)
                        state.finish_cycle(duration)

                        passing = sum(1 for d in diagnostics if d.overall_status == CheckStatus.PASS)
                        warning = sum(1 for d in diagnostics if d.overall_status == CheckStatus.WARN)
                        failing = len(diagnostics) - passing - warning
                        ts = time.strftime("%H:%M:%S")
                        console.print(
                            f"[dim]{ts}[/dim]  cycle done  "
                            f"[green]{passing} pass[/green] · "
                            f"[yellow]{warning} warn[/yellow] · "
                            f"[red]{failing} fail[/red]  "
                            f"[dim]{duration:.1f}s · next in {interval}s[/dim]"
                        )
                    except Exception as e:
                        state.mark_cycle_error(str(e))
                        log.error("Analysis cycle failed", error=str(e))
                        console.print(f"[red]✗[/red] Cycle error: {e}")

                    await asyncio.sleep(interval)
            except (asyncio.CancelledError, KeyboardInterrupt):
                console.print("\n[dim]Shutting down...[/dim]")
            finally:
                await runner.cleanup()
            return 0

        else:
            # Normal one-shot analysis (default) or --watch (loop in the future)
            diagnostics = await _run_once()
            console.print()
            if json_output:
                print(_diagnostics_to_json(diagnostics))
            else:
                _print_analysis_results(diagnostics, only_failed=only_failed, only_passed=only_passed)

        return 0

    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        log.error("Analysis failed", error=str(e))
        return 1


async def cmd_check(args: argparse.Namespace) -> int:
    """Single domain step-by-step diagnosis."""
    domain: str = args.domain
    port: int = args.port
    timeout: int = args.timeout or settings.censor_check_timeout
    subscription_url: str | None = getattr(args, "subscription", None)

    if subscription_url:
        return await _cmd_check_via_subscription(domain, port, timeout, subscription_url)

    raw_proxy: str | None = args.proxy or settings.censor_check_proxy_url

    try:
        async with _xray_proxy_context(raw_proxy) as proxy_url:
            console.print()
            console.print(
                Panel(
                    f"[bold cyan]Diagnosing: {domain}[/bold cyan]\n"
                    f"[dim]{'Via proxy: ' + proxy_url if proxy_url else 'Direct connection (no proxy)'}[/dim]",
                    border_style="blue",
                    padding=(0, 2),
                )
            )
            console.print()

            with Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task("[dim]Starting...[/dim]", total=None)

                def on_step_start(step_name: str) -> None:
                    progress.update(task_id, description=f"[dim]{step_name}...[/dim]")

                def on_step_complete(result: DiagnosticResult) -> None:
                    icon, color = _status_icon_and_color(result.status)
                    dur = f"  [dim]{result.duration_ms:.0f}ms[/dim]" if result.duration_ms else ""
                    msg = result.message
                    if result.status == CheckStatus.SKIP:
                        progress.console.print(f"  [dim]○ {result.check_name:<14}  {msg}[/dim]")
                    else:
                        progress.console.print(
                            f"  [{color}]{icon}[/{color}] [bold]{result.check_name:<14}[/bold]  {msg}{dur}"
                        )

                diagnostic = await check_domain_verbose(
                    domain,
                    port=port,
                    proxy_url=proxy_url or "",
                    timeout=timeout,
                    on_step_complete=on_step_complete,
                    on_step_start=on_step_start,
                )

            # Summary panel
            if diagnostic.overall_status == CheckStatus.PASS:
                status_text, border = "[bold green]✓  PASS[/bold green]", "green"
            elif diagnostic.overall_status == CheckStatus.WARN:
                status_text, border = "[bold yellow]⚠  WARN[/bold yellow]", "yellow"
            else:
                status_text, border = "[bold red]✗  FAIL[/bold red]", "red"

            console.print()
            console.print(
                Panel(
                    status_text,
                    title=f"[bold]{domain}[/bold]",
                    border_style=border,
                    padding=(0, 2),
                )
            )

            if diagnostic.recommendations:
                console.print()
                console.print("[bold yellow]Recommendations:[/bold yellow]")
                for rec in diagnostic.recommendations:
                    console.print(f"  → {rec}")

            return 0 if diagnostic.overall_status in (CheckStatus.PASS, CheckStatus.WARN) else 1
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        return 1


async def _cmd_check_via_subscription(domain: str, port: int, timeout: int, subscription_url: str) -> int:
    """Check a domain through all proxies from a subscription URL."""
    try:
        # Ensure Xray binary is available
        with console.status("[dim]Checking Xray binary...[/dim]", spinner="dots"):
            xray_path = await ensure_xray(settings.xray_binary_path)
        if xray_path:
            settings.xray_binary_path = xray_path
        else:
            error_console.print(
                "[bold red]✗ Xray binary not found — required for subscription proxy testing[/bold red]"
            )
            return 1

        # Fetch subscription proxies
        with console.status("[dim]Fetching subscription...[/dim]", spinner="dots"):
            shares = await fetch_subscription(subscription_url)

        if not shares:
            error_console.print("[bold red]✗ No proxies found in subscription[/bold red]")
            return 1

        # Filter out virtual/invalid hosts
        valid_shares = [s for s in shares if _is_valid_server_address(s.server)]
        skipped = len(shares) - len(valid_shares)

        console.print(
            f"[green]✓[/green] Loaded [bold]{len(valid_shares)}[/bold] proxies from subscription"
            + (f" [dim]({skipped} skipped)[/dim]" if skipped else "")
        )
        console.print()
        console.print(
            Panel(
                f"[bold cyan]Checking: {domain}[/bold cyan]\n"
                f"[dim]Testing through {len(valid_shares)} subscription proxies[/dim]",
                border_style="blue",
                padding=(0, 2),
            )
        )
        console.print()

    except Exception as e:
        error_console.print(f"[bold red]Error fetching subscription: {e}[/bold red]")
        return 1

    # Run checks in parallel (max 8 concurrent xray instances)
    results: list[tuple[str, CheckStatus]] = [("", CheckStatus.FAIL)] * len(valid_shares)
    semaphore = asyncio.Semaphore(8)

    async def _check_one(idx: int, share) -> None:
        label = share.name or f"{share.server}:{share.port}"
        async with semaphore:
            try:
                async with _xray_proxy_context(share.raw_url, silent=True) as proxy_url:
                    diagnostic = await check_domain_verbose(
                        domain,
                        port=port,
                        proxy_url=proxy_url or "",
                        timeout=timeout,
                    )
                    status = diagnostic.overall_status
            except Exception as e:
                log.debug(f"Error testing via {label}: {e}")
                status = CheckStatus.FAIL

        results[idx] = (label, status)
        icon, color = _status_icon_and_color(status)
        progress.console.print(f"  [{color}]{icon}[/{color}] [bold]{label}[/bold]")
        progress.advance(task_id)

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task(
            f"[cyan]Checking via {len(valid_shares)} proxies[/cyan]",
            total=len(valid_shares),
        )
        await asyncio.gather(*[_check_one(i, s) for i, s in enumerate(valid_shares)])

    # Summary table
    console.print()
    pass_count = sum(1 for _, s in results if s in (CheckStatus.PASS, CheckStatus.WARN))
    fail_count = len(results) - pass_count

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Proxy", style="cyan", no_wrap=False)
    table.add_column("", justify="left", width=10)

    for label, status in results:
        icon, color = _status_icon_and_color(status)
        table.add_row(label, f"[{color}]{icon} {status.value}[/{color}]")

    console.print(table)
    console.print(
        f"\n[bold green]{pass_count} passed[/bold green], [bold red]{fail_count} failed[/bold red]"
        f" out of [bold]{len(results)}[/bold] proxies"
    )

    return 0 if pass_count > 0 else 1


async def cmd_scan(args: argparse.Namespace) -> int:
    """Bulk domain censorship scan."""
    domains: list[str] = args.domains or []
    domain_list: str = args.list
    raw_proxy: str | None = args.proxy or settings.censor_check_proxy_url
    timeout: int = args.timeout or settings.censor_check_timeout
    max_parallel: int = args.max_parallel or settings.censor_check_max_parallel

    # --file takes priority over positional domains and --list
    if getattr(args, "file", None):
        domains = load_domains_file(args.file)
        console.print()

    # Fall back to config domains if nothing given
    if not domains and settings.censor_check_domains:
        domains = [d.strip() for d in settings.censor_check_domains.split(",") if d.strip()]

    # Resolve domain list (None = use DEFAULT_CENSOR_DOMAINS inside run_censor_check)
    resolved: list[str] | None = domains or None
    if resolved is None and domain_list != "default":
        if domain_list == "whitelist":
            list_label = "Russia mobile internet whitelist"
            fetch_coro = fetch_whitelist_domains()
        else:
            _, list_label = ALLOW_DOMAINS_LISTS[domain_list]
            fetch_coro = fetch_allow_domains_list(domain_list)

        with console.status(f"[dim]Fetching {list_label}...[/dim]", spinner="dots"):
            resolved = await fetch_coro
        if not resolved:
            error_console.print(f"[bold red]✗[/bold red] Failed to fetch '{domain_list}' — using built-in list")
        else:
            console.print(
                f"[green]✓[/green] Loaded [bold]{len(resolved)}[/bold] domains from [cyan]{list_label}[/cyan]"
            )
            console.print()

    domain_count = len(resolved) if resolved else len(DEFAULT_CENSOR_DOMAINS)

    try:
        async with _xray_proxy_context(raw_proxy) as proxy_url:
            console.print()
            console.print(
                Panel(
                    f"[bold cyan]🌐  Censorship Scan[/bold cyan]\n"
                    f"[dim]{'Via proxy: ' + proxy_url if proxy_url else 'Direct connection (no proxy)'}[/dim]",
                    border_style="blue",
                    padding=(0, 2),
                )
            )
            console.print()

            with Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=28),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                task_id = progress.add_task(f"[cyan]Scanning {domain_count} domains[/cyan]", total=domain_count)

                def on_domain_complete(result: DomainCheckResult) -> None:
                    if result.status == DomainStatus.OK:
                        icon, label = "[green]✓[/green]", "[green]OK[/green]     "
                    elif result.status == DomainStatus.BLOCKED:
                        icon = "[red]✗[/red]"
                        bt = f" [dim]({result.block_type})[/dim]" if result.block_type else ""
                        label = f"[red]BLOCKED[/red]{bt}"
                    else:
                        icon = "[yellow]⚠[/yellow]"
                        bt = f" [dim]({result.block_type})[/dim]" if result.block_type else ""
                        label = f"[yellow]PARTIAL[/yellow]{bt}"

                    extras = []
                    if result.tls_valid:
                        extras.append("[dim]TLS✓[/dim]")
                    elif result.status != DomainStatus.BLOCKED:
                        extras.append("[dim]TLS✗[/dim]")
                    if result.https_code:
                        extras.append(f"[dim]HTTPS {result.https_code}[/dim]")
                    elif result.http_code:
                        extras.append(f"[dim]HTTP {result.http_code}[/dim]")
                    if result.details.get("rkn_stub_ip"):
                        extras.append(f"[dim]stub:{result.details['rkn_stub_ip']}[/dim]")

                    extras_str = "  " + "  ".join(extras) if extras else ""
                    progress.console.print(f"  {icon} [bold]{result.domain:<26}[/bold]{label}{extras_str}")
                    progress.advance(task_id)

                summary = await run_censor_check(
                    domains=resolved,
                    proxy_url=proxy_url or "",
                    timeout=timeout,
                    max_parallel=max_parallel,
                    on_domain_complete=on_domain_complete,
                )

            _print_censor_check_results(summary)
            return 1 if summary.blocked > 0 else 0
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        log.error("Scan failed", error=str(e))
        return 1


async def _run_dpi_iteration(state: MetricsState) -> None:
    """Run one iteration of each enabled DPI probe and feed the MetricsState.

    Probes run sequentially to keep resource usage predictable — they are
    already concurrent internally. Each probe is isolated: a failure in one
    does not prevent the others from running.
    """
    dns_domains_raw = settings.serve_dpi_dns_domains.strip()
    if settings.serve_dpi_dns_enabled and dns_domains_raw:
        domains = [d.strip() for d in dns_domains_raw.split(",") if d.strip()]
        t0 = time.monotonic()
        try:
            report = await probe_dns_integrity(domains, timeout=settings.dns_dpi_timeout)
            state.update_dpi_dns(report, time.monotonic() - t0)
            log.info(
                "DPI DNS probe done",
                domains=len(domains),
                stub_ips=len(report.stub_ips),
                duration_s=round(time.monotonic() - t0, 2),
            )
        except Exception as e:
            state.mark_dpi_dns_error(str(e))
            log.warning("DPI DNS probe failed", error=str(e))

    if settings.serve_dpi_cdn_enabled:
        t0 = time.monotonic()
        try:
            targets = load_targets()
            if settings.serve_dpi_cdn_limit > 0:
                targets = targets[: settings.serve_dpi_cdn_limit]
            report = await scan_targets(
                targets,
                max_parallel=settings.serve_dpi_cdn_max_parallel,
                iterations=settings.fat_probe_iterations,
                chunk_size=settings.fat_probe_chunk_size,
                connect_timeout=settings.fat_probe_connect_timeout,
                read_timeout=settings.fat_probe_read_timeout,
                default_sni=settings.fat_probe_default_sni,
            )
            state.update_dpi_cdn(report, time.monotonic() - t0)
            log.info(
                "DPI CDN probe done",
                targets=len(targets),
                overall=report.overall_verdict,
                duration_s=round(time.monotonic() - t0, 2),
            )
        except Exception as e:
            state.mark_dpi_cdn_error(str(e))
            log.warning("DPI CDN probe failed", error=str(e))

    if settings.serve_dpi_telegram_enabled:
        t0 = time.monotonic()
        try:
            report = await check_telegram(
                stall_timeout=settings.telegram_stall_timeout,
                total_timeout=settings.telegram_total_timeout,
            )
            state.update_dpi_telegram(report, time.monotonic() - t0)
            log.info(
                "DPI Telegram probe done",
                verdict=report.verdict,
                duration_s=round(time.monotonic() - t0, 2),
            )
        except Exception as e:
            state.mark_dpi_telegram_error(str(e))
            log.warning("DPI Telegram probe failed", error=str(e))


async def _dpi_loop(state: MetricsState) -> None:
    """Periodic DPI probe loop run alongside the main scan loop in `serve`."""
    interval = settings.serve_dpi_interval_seconds
    while True:
        try:
            await _run_dpi_iteration(state)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # defensive: keep the loop alive on unexpected errors
            log.error("DPI iteration crashed", error=str(e))
        await asyncio.sleep(interval)


def _any_dpi_probe_enabled() -> bool:
    dns_on = settings.serve_dpi_dns_enabled and bool(settings.serve_dpi_dns_domains.strip())
    return dns_on or settings.serve_dpi_cdn_enabled or settings.serve_dpi_telegram_enabled


async def cmd_serve(args: argparse.Namespace) -> int:
    """Start Prometheus metrics server with periodic censorship scans."""
    port: int = args.port or settings.metrics_port
    host: str = args.host or settings.metrics_host
    interval: int = args.interval or settings.check_interval_seconds
    domains_list: list[str] = args.domains or []
    domain_list_name: str = args.list
    raw_proxy: str | None = args.proxy or settings.censor_check_proxy_url
    timeout: int = args.timeout or settings.censor_check_timeout
    max_parallel: int = args.max_parallel or settings.censor_check_max_parallel

    # --subscription: fetch all valid proxies and scan through each of them
    subscription_url: str | None = getattr(args, "subscription", None)
    sub_shares: list = []
    if subscription_url:
        xray_path = await ensure_xray(settings.xray_binary_path)
        if not xray_path:
            error_console.print("[bold red]✗ Xray binary not found — required for subscription proxy[/bold red]")
            return 1
        settings.xray_binary_path = xray_path
        with console.status("[dim]Fetching subscription...[/dim]", spinner="dots"):
            shares = await fetch_subscription(subscription_url)
        sub_shares = [s for s in shares if _is_valid_server_address(s.server)]
        if not sub_shares:
            error_console.print("[bold red]✗ No valid proxies found in subscription[/bold red]")
            return 1
        console.print(f"[green]✓[/green] Loaded [bold]{len(sub_shares)}[/bold] proxies from subscription")

    # --file takes priority over positional domains and --list
    if getattr(args, "file", None):
        domains_list = load_domains_file(args.file)
        console.print()

    # Resolve domains (mirrors cmd_scan logic)
    if not domains_list and settings.censor_check_domains:
        domains_list = [d.strip() for d in settings.censor_check_domains.split(",") if d.strip()]

    resolved: list[str] | None = domains_list or None
    if resolved is None and domain_list_name != "default":
        if domain_list_name == "whitelist":
            list_label = "Russia mobile internet whitelist"
            fetch_coro = fetch_whitelist_domains()
        else:
            _, list_label = ALLOW_DOMAINS_LISTS[domain_list_name]
            fetch_coro = fetch_allow_domains_list(domain_list_name)

        with console.status(f"[dim]Fetching {list_label}...[/dim]", spinner="dots"):
            resolved = await fetch_coro
        if not resolved:
            console.print(f"[yellow]⚠[/yellow] Failed to fetch '{domain_list_name}' — using built-in list")

    domain_count = len(resolved) if resolved else len(DEFAULT_CENSOR_DOMAINS)

    state = MetricsState()
    state.domain_count = domain_count

    if sub_shares:
        proxy_summary = f"{len(sub_shares)} proxies from subscription"
        for share in sub_shares:
            label = share.name or f"{share.server}:{share.port}"
            state.register_proxy(label)
    else:
        proxy_summary = raw_proxy or "direct connection"

    try:
        console.print()
        console.print(
            Panel(
                f"[bold cyan]Metrics server[/bold cyan]\n"
                f"[green]http://{host}:{port}/metrics[/green]\n"
                f"[dim]{domain_count} domains · scan every {interval}s · {proxy_summary}[/dim]",
                border_style="blue",
                padding=(0, 2),
            )
        )
        console.print()

        runner = await run_metrics_server(host, port, state)
        console.print(f"[green]✓[/green] Listening on [bold]http://{host}:{port}/metrics[/bold]  (Ctrl+C to stop)\n")

        dpi_task: asyncio.Task | None = None
        if settings.serve_dpi_enabled and _any_dpi_probe_enabled():
            dpi_task = asyncio.create_task(_dpi_loop(state), name="serve-dpi-loop")
            enabled = [
                name
                for name, on in (
                    ("DNS", settings.serve_dpi_dns_enabled and bool(settings.serve_dpi_dns_domains.strip())),
                    ("CDN", settings.serve_dpi_cdn_enabled),
                    ("Telegram", settings.serve_dpi_telegram_enabled),
                )
                if on
            ]
            console.print(
                f"[green]✓[/green] DPI probes enabled: [bold]{', '.join(enabled)}[/bold]  "
                f"[dim](every {settings.serve_dpi_interval_seconds}s)[/dim]\n"
            )

        try:
            while True:
                if sub_shares:
                    # Scan through all proxies in parallel (max 8 concurrent Xray instances)
                    cycle_t0 = time.monotonic()
                    sem = asyncio.Semaphore(8)

                    with Progress(
                        SpinnerColumn(spinner_name="dots"),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(bar_width=28),
                        MofNCompleteColumn(),
                        TaskProgressColumn(),
                        TimeElapsedColumn(),
                        console=console,
                        transient=True,
                    ) as progress:
                        task_id = progress.add_task(
                            f"[cyan]Scanning {len(sub_shares)} proxies[/cyan]",
                            total=len(sub_shares),
                        )

                        async def _scan_one_proxy(share, _sem=sem, _prog=progress, _tid=task_id) -> None:
                            label = share.name or f"{share.server}:{share.port}"
                            async with _sem:
                                t0 = time.monotonic()
                                try:
                                    # Pre-check: verify proxy host is reachable before starting Xray.
                                    # If the host is down, Xray starts fine (local listener only) but all
                                    # domain checks will fail — making every domain appear blocked.
                                    try:
                                        _r, _w = await asyncio.wait_for(
                                            asyncio.open_connection(share.server, share.port),
                                            timeout=settings.tcp_timeout,
                                        )
                                        _w.close()
                                        await _w.wait_closed()
                                    except Exception as tcp_err:
                                        err_msg = f"host unreachable ({share.server}:{share.port}): {tcp_err}"
                                        state.mark_error(err_msg, proxy_label=label)
                                        log.warning(
                                            "Proxy host unreachable, skipping scan", proxy=label, error=str(tcp_err)
                                        )
                                        _prog.console.print(
                                            f"  [yellow]⚠[/yellow] [bold]{label}[/bold]  "
                                            f"[dim]host unreachable — scan skipped[/dim]"
                                        )
                                        return

                                    async with _xray_proxy_context(share.raw_url, silent=True) as proxy_url:
                                        summary = await run_censor_check(
                                            domains=resolved,
                                            proxy_url=proxy_url or "",
                                            timeout=timeout,
                                            max_parallel=max_parallel,
                                        )
                                    duration = time.monotonic() - t0
                                    state.update(summary, duration, proxy_label=label)
                                    _prog.console.print(
                                        f"  [green]✓[/green] [bold]{label}[/bold]  "
                                        f"[green]{summary.ok} OK[/green] · "
                                        f"[red]{summary.blocked} blocked[/red] · "
                                        f"[yellow]{summary.partial} partial[/yellow]  "
                                        f"[dim]{duration:.1f}s[/dim]"
                                    )
                                except Exception as e:
                                    state.mark_error(str(e), proxy_label=label)
                                    log.error("Scan failed", proxy=label, error=str(e))
                                    _prog.console.print(f"  [red]✗[/red] [bold]{label}[/bold]  [dim]{e}[/dim]")
                                finally:
                                    _prog.advance(_tid)

                        await asyncio.gather(*[_scan_one_proxy(s) for s in sub_shares])

                    cycle_duration = time.monotonic() - cycle_t0
                    ts = time.strftime("%H:%M:%S")
                    console.print(
                        f"[dim]{ts}[/dim]  cycle done  "
                        f"[dim]{len(sub_shares)} proxies · {cycle_duration:.1f}s · next in {interval}s[/dim]"
                    )
                else:
                    async with _xray_proxy_context(raw_proxy) as proxy_url:
                        t0 = time.monotonic()
                        try:
                            summary = await run_censor_check(
                                domains=resolved,
                                proxy_url=proxy_url or "",
                                timeout=timeout,
                                max_parallel=max_parallel,
                            )
                            duration = time.monotonic() - t0
                            state.update(summary, duration)
                            ts = time.strftime("%H:%M:%S")
                            console.print(
                                f"[dim]{ts}[/dim]  scan done  "
                                f"[green]{summary.ok} OK[/green] · "
                                f"[red]{summary.blocked} blocked[/red] · "
                                f"[yellow]{summary.partial} partial[/yellow]  "
                                f"[dim]{duration:.1f}s · next in {interval}s[/dim]"
                            )
                        except Exception as e:
                            state.mark_error(str(e))
                            log.error("Scan failed", error=str(e))
                            console.print(f"[red]✗[/red] Scan error: {e}")

                await asyncio.sleep(interval)
        except asyncio.CancelledError, KeyboardInterrupt:
            console.print("\n[dim]Shutting down...[/dim]")
        finally:
            if dpi_task is not None and not dpi_task.done():
                dpi_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await dpi_task
            await runner.cleanup()

        return 0
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        return 1


def _print_proxy_progress_line(
    progress: Progress, diag: HostDiagnostic, protocol: str, max_host_width: int = 0
) -> None:
    """Print a single per-proxy progress line under the active Progress bar.

    Mirrors the cmd_scan callback style: icon + colored status label + dim extras.
    """
    if diag.overall_status == CheckStatus.PASS:
        label = "[green]OK[/green]     "
    elif diag.overall_status == CheckStatus.WARN:
        label = "[yellow]WARN[/yellow]   "
    else:
        label = "[red]PROBLEM[/red]"

    extras: list[str] = []

    def _find(check_name: str) -> DiagnosticResult | None:
        for r in diag.results:
            if r.check_name == check_name:
                return r
        return None

    def _color(label: str, status: CheckStatus | None, *, extra: str = "") -> str:
        """Return a Rich-markup tag: green/yellow/red/dim based on status."""
        text = f"{label}{extra}" if extra else label
        if status is None or status == CheckStatus.SKIP:
            return f"[dim]{text}[/dim]"
        if status == CheckStatus.PASS:
            return f"[green]{text}[/green]"
        if status in (CheckStatus.WARN, CheckStatus.TIMEOUT):
            return f"[yellow]{text}[/yellow]"
        return f"[red]{text}[/red]"

    # Order matches the check pipeline: TCP → ICMP → DPI → Xray

    # TCP
    tcp_r = _find("TCP Connection")
    extras.append(_color("tcp", tcp_r.status if tcp_r else None))

    # ICMP
    icmp_r = _find("ICMP Ping")
    extras.append(_color("icmp", icmp_r.status if icmp_r else None))

    # DPI fat probe
    dpi_r = _find("TCP 16-20 KB Fat Probe")
    if dpi_r and dpi_r.details.get("label") == "tcp_16_20":
        extras.append("[red]dpi:throttle[/red]")
    else:
        extras.append(_color("dpi", dpi_r.status if dpi_r else None))

    # Xray / proxy connectivity — pick the first matching result
    xray_r = None
    for r in sorted(diag.results, key=_check_sort_key):
        if "xray connectivity" in r.check_name.lower():
            xray_r = r
            break
    extras.append(_color("xray", xray_r.status if xray_r else None))

    extras_str = "  " + "  ".join(extras) if extras else ""
    proto_tag = f"[dim]({protocol})[/dim]" if protocol else ""
    host_part = f"[bold]{diag.host}[/bold] {proto_tag}"
    host_cell_len = Text.from_markup(host_part).cell_len
    pad = " " * max(0, max_host_width - host_cell_len)
    progress.console.print(f"  {host_part}{pad}  {label}{extras_str}")


def _diagnostics_to_json(diagnostics: list[HostDiagnostic]) -> str:
    """Serialize diagnostics to JSON for machine consumption."""
    data = []
    for diag in diagnostics:
        host_data = {
            "host": diag.host,
            "overall_status": str(diag.overall_status),
            "recommendations": diag.recommendations,
            "checks": [],
        }
        for r in sorted(diag.results, key=_check_sort_key):
            check = {
                "name": r.check_name,
                "status": str(r.status),
                "severity": str(r.severity),
                "message": r.message,
                "duration_ms": r.duration_ms,
                "details": r.details,
            }
            host_data["checks"].append(check)
        data.append(host_data)
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _print_watch_diff(
    prev: list[HostDiagnostic],
    curr: list[HostDiagnostic],
) -> None:
    """Print status changes between watch iterations."""
    prev_map = {d.host: d.overall_status for d in prev if d.results}
    curr_map = {d.host: d.overall_status for d in curr if d.results}

    changes: list[str] = []
    for host, new_status in curr_map.items():
        old_status = prev_map.get(host)
        if old_status is None:
            changes.append(f"  [cyan]+ {host}[/cyan] → {new_status}")
        elif old_status != new_status:
            old_icon, old_color = _status_icon_and_color(old_status)
            new_icon, new_color = _status_icon_and_color(new_status)
            changes.append(f"  [{old_color}]{old_icon}[/{old_color}] → [{new_color}]{new_icon}[/{new_color}]  {host}")

    for host in prev_map:
        if host not in curr_map:
            changes.append(f"  [dim]- {host} (removed)[/dim]")

    if changes:
        console.print(Panel("\n".join(changes), title="[bold]Changes since last run[/bold]", border_style="blue"))
        console.print()


def _print_analysis_results(
    diagnostics: list[HostDiagnostic],
    only_failed: bool = False,
    only_passed: bool = False,
) -> None:
    """Print full analysis results with detailed check-by-check breakdown."""
    if not diagnostics:
        console.print("[yellow]No proxies to analyze[/yellow]")
        return

    # Filter out skipped virtual/invalid hosts (no results means host was skipped —
    # subscription section dividers, gateway placeholders, malformed entries).
    real_diagnostics = [d for d in diagnostics if d.results]
    skipped_hosts = [d for d in diagnostics if not d.results]

    if skipped_hosts:
        console.print(f"[dim]○ Skipped {len(skipped_hosts)} non-proxy subscription entries[/dim]")

    if not real_diagnostics:
        console.print("[yellow]No real hosts to analyze (only virtual/skipped hosts)[/yellow]")
        return

    # Separate into passing, warn, and failing hosts
    passing = [d for d in real_diagnostics if d.overall_status == CheckStatus.PASS]
    warning = [d for d in real_diagnostics if d.overall_status == CheckStatus.WARN]
    failing = [d for d in real_diagnostics if d.overall_status not in (CheckStatus.PASS, CheckStatus.WARN)]

    # === SUMMARY HEADER (always shows real counts) ===
    warn_part = f"  |  [yellow]⚠ WARN:[/yellow] {len(warning)}" if warning else ""
    console.print()
    console.print(
        Panel(
            f"[bold]Total hosts:[/bold] {len(real_diagnostics)}  |  "
            f"[green]✓ OK:[/green] {len(passing)}"
            f"{warn_part}  |  "
            f"[red]✗ PROBLEMS:[/red] {len(failing)}",
            title="[bold blue]Analysis Result[/bold blue]",
            border_style="green" if not failing else "red",
        )
    )

    # Apply output filters (after summary so counts are accurate)
    if only_failed:
        passing = []
        warning = []
    if only_passed:
        failing = []
    console.print()

    # WARN hosts go into the passing compact table (they work with caveats)
    passing_and_warn = passing + warning

    # Sort: OK first, then WARN; within each group — by ping latency
    # Prefer ICMP ping for sorting (always available), fall back to TCP ping
    def _ping_sort_key(diag: HostDiagnostic) -> tuple[int, float]:
        group = 0 if diag.overall_status == CheckStatus.PASS else 1
        for r in diag.results:
            if "ICMP Ping" in r.check_name and r.details.get("latency_avg_ms") is not None:
                return (group, r.details["latency_avg_ms"])
        for r in diag.results:
            if "TCP Ping" in r.check_name and r.status == CheckStatus.PASS:
                return (group, r.details.get("latency_avg_ms", 9999.0))
        return (group, 9999.0)

    passing_and_warn.sort(key=_ping_sort_key)

    # === PASSING + WARN HOSTS (compact) ===
    if passing_and_warn:
        console.print("[bold green]✓ WORKING HOSTS[/bold green]\n")

        # Detect which optional columns have data in any diagnostic
        all_results = [r for d in passing_and_warn for r in d.results]
        has_dpi = any(r.check_name == "TCP 16-20 KB Fat Probe" for r in all_results)
        has_censor = any(r.check_name == "Censor Canary" for r in all_results)
        has_telegram = any(r.check_name == "Telegram Reachability" for r in all_results)

        has_icmp = any(r.check_name == "ICMP Ping" for r in all_results)

        table = Table(show_header=True, box=None, padding=(0, 2))
        table.add_column("Host", style="cyan")
        if has_icmp:
            table.add_column("ICMP", justify="right")
        table.add_column("Ping", justify="right")
        table.add_column("DNS", justify="center")
        table.add_column("TCP", justify="center")
        if has_dpi:
            table.add_column("DPI", justify="center")
        table.add_column("Proxy", justify="center")
        if has_censor:
            table.add_column("Censor", justify="center")
        if has_telegram:
            table.add_column("TG", justify="center")
        table.add_column("Exit IP", justify="left", style="dim")

        warn_separator_added = False
        for diag in passing_and_warn:
            # Visual separator between OK and WARN groups
            if not warn_separator_added and diag.overall_status == CheckStatus.WARN:
                warn_separator_added = True
                num_cols = 5 + has_icmp + has_dpi + has_censor + has_telegram + 1  # +1 for Exit IP
                table.add_row(*[""] * num_cols)
                table.add_row(*["[dim]⚠ with minor issues[/dim]"] + [""] * (num_cols - 1))

            dns = _check_status_icon(diag, "DNS Resolution")
            tcp = _check_status_icon(diag, "TCP Connection")
            proxy = _check_status_icon(diag, "Xray Connectivity") or _check_status_icon(diag, "Tunnel")

            # Ping columns
            ping_text = _format_ping(diag, "TCP Ping")
            icmp_text = _format_ping(diag, "ICMP Ping") if has_icmp else None

            # Exit IP
            exit_ip = ""
            for r in diag.results:
                if "Exit IP" in r.check_name and r.status == CheckStatus.PASS:
                    exit_ip = r.details.get("exit_ip", "")
                    break

            row = [diag.host]
            if has_icmp:
                row.append(icmp_text)
            row.extend([ping_text, dns, tcp])
            if has_dpi:
                row.append(_check_status_icon(diag, "Fat Probe"))
            row.append(proxy)
            if has_censor:
                row.append(_check_status_icon(diag, "Censor Canary"))
            if has_telegram:
                row.append(_check_status_icon(diag, "Telegram Reachability"))
            row.append(exit_ip)

            table.add_row(*row)

        console.print(table)
        console.print()

    # === PROBLEM HOSTS (compact table + detailed recommendations) ===
    if failing:
        console.print("[bold red]✗ HOSTS WITH PROBLEMS[/bold red]\n")

        # Compact table — same format as working hosts
        fail_results = [r for d in failing for r in d.results]
        f_has_dpi = any(r.check_name == "TCP 16-20 KB Fat Probe" for r in fail_results)
        f_has_censor = any(r.check_name == "Censor Canary" for r in fail_results)
        f_has_telegram = any(r.check_name == "Telegram Reachability" for r in fail_results)
        f_has_icmp = any(r.check_name == "ICMP Ping" for r in fail_results)

        fail_table = Table(show_header=True, box=None, padding=(0, 2))
        fail_table.add_column("Host", style="cyan")
        if f_has_icmp:
            fail_table.add_column("ICMP", justify="right")
        fail_table.add_column("Ping", justify="right")
        fail_table.add_column("DNS", justify="center")
        fail_table.add_column("TCP", justify="center")
        if f_has_dpi:
            fail_table.add_column("DPI", justify="center")
        fail_table.add_column("Proxy", justify="center")
        if f_has_censor:
            fail_table.add_column("Censor", justify="center")
        if f_has_telegram:
            fail_table.add_column("TG", justify="center")
        fail_table.add_column("Exit IP", justify="left", style="dim")

        for diag in failing:
            dns = _check_status_icon(diag, "DNS Resolution")
            tcp = _check_status_icon(diag, "TCP Connection")
            proxy = _check_status_icon(diag, "Xray Connectivity") or _check_status_icon(diag, "Tunnel")
            ping_text = _format_ping(diag, "TCP Ping")
            icmp_text = _format_ping(diag, "ICMP Ping") if f_has_icmp else None

            exit_ip = ""
            for r in diag.results:
                if "Exit IP" in r.check_name and r.status == CheckStatus.PASS:
                    exit_ip = r.details.get("exit_ip", "")
                    break

            row = [diag.host]
            if f_has_icmp:
                row.append(icmp_text)
            row.extend([ping_text, dns, tcp])
            if f_has_dpi:
                row.append(_check_status_icon(diag, "Fat Probe"))
            row.append(proxy)
            if f_has_censor:
                row.append(_check_status_icon(diag, "Censor Canary"))
            if f_has_telegram:
                row.append(_check_status_icon(diag, "Telegram Reachability"))
            row.append(exit_ip)

            fail_table.add_row(*row)

        console.print(fail_table)
        console.print()

        # Detailed recommendations
        console.print("[bold yellow]⚠ RECOMMENDATIONS[/bold yellow]\n")

        # Group hosts whose check fingerprint is identical AND whose
        # host-normalized recommendations are identical. Iteration preserves
        # the original "failing" order so output stays stable across runs.
        groups: list[tuple[tuple, tuple, list[HostDiagnostic]]] = []
        index: dict[tuple, int] = {}
        for diag in failing:
            check_fp = _problem_fingerprint(diag)
            rec_fp = tuple(_normalize_recommendation(r, diag.host) for r in diag.recommendations)
            key = (check_fp, rec_fp)
            if key in index:
                groups[index[key]][2].append(diag)
            else:
                index[key] = len(groups)
                groups.append((check_fp, rec_fp, [diag]))

        for _check_fp, _rec_fp, members in groups:
            head = members[0]
            if len(members) == 1:
                console.print(f"  [bold cyan]→ {head.host}[/bold cyan]")
            else:
                console.print(f"  [bold cyan]→ {len(members)} hosts with the same symptom:[/bold cyan]")
                for m in members:
                    console.print(f"     [cyan]• {m.host}[/cyan]")
            console.print(f"  [dim]{'─' * 60}[/dim]")
            console.print(Padding(_build_host_table(head), (0, 0, 0, 4)))

            if head.recommendations:
                console.print("    [bold yellow]What to do:[/bold yellow]")
                for rec in _compact_recommendations(head.recommendations):
                    # Replace this group-leader's host token with <host> when
                    # the group has multiple members, otherwise show as-is.
                    rendered = _normalize_recommendation(rec, head.host) if len(members) > 1 else rec
                    console.print(f"      → {rendered}")

            console.print()


def _format_ping(diag: HostDiagnostic, check_name: str = "TCP Ping") -> str:
    """Format ping column: show latency with color based on status."""
    for r in diag.results:
        if check_name not in r.check_name:
            continue
        avg_ms = r.details.get("latency_avg_ms")
        if avg_ms is not None:
            # Round to integer for clean display
            ms = round(avg_ms)
            if r.status == CheckStatus.PASS:
                if ms < 50:
                    return f"[green]{ms}ms[/green]"
                elif ms < 200:
                    return f"[yellow]{ms}ms[/yellow]"
                else:
                    return f"[red]{ms}ms[/red]"
            elif r.status == CheckStatus.WARN:
                loss = r.details.get("packet_loss_pct")
                loss_hint = f" {loss:.0f}%loss" if loss else ""
                return f"[yellow]{ms}ms{loss_hint}[/yellow]"
            else:
                return f"[red]{ms}ms[/red]"
        # No latency data — fall back to icon
        if r.status == CheckStatus.FAIL:
            return "[red]✗[/red]"
        if r.status == CheckStatus.TIMEOUT:
            return "[yellow]⏱[/yellow]"
        return _check_status_icon(diag, check_name)
    return "[dim]–[/dim]"


def _check_status_icon(diagnostic: HostDiagnostic, check_name_part: str) -> str:
    """Get a compact status icon for a check."""
    for result in diagnostic.results:
        if check_name_part.lower() in result.check_name.lower():
            if result.status == CheckStatus.PASS:
                return "[green]✓[/green]"
            elif result.status == CheckStatus.WARN:
                return "[yellow]⚠[/yellow]"
            elif result.status == CheckStatus.FAIL:
                return "[red]✗[/red]"
            elif result.status == CheckStatus.TIMEOUT:
                return "[yellow]⏱[/yellow]"
            else:
                return "[dim]–[/dim]"
    return "[dim]–[/dim]"


def _status_icon_and_color(status: CheckStatus) -> tuple[str, str]:
    """Get icon and color for a check status."""
    return {
        CheckStatus.PASS: ("✓", "green"),
        CheckStatus.WARN: ("⚠", "yellow"),
        CheckStatus.FAIL: ("✗", "red"),
        CheckStatus.TIMEOUT: ("⏱", "yellow"),
        CheckStatus.SKIP: ("○", "dim"),
    }.get(status, ("?", "white"))


# Canonical render order for checks — keeps the per-host block stable regardless
# of which async task completed first. Lower number = printed earlier.
_CHECK_ORDER: list[tuple[str, int]] = [
    ("DNS Resolution", 10),
    ("DNS Integrity", 12),
    ("TCP Connection", 20),
    ("ICMP Ping", 25),
    ("TCP Ping", 30),
    ("TCP 16-20 KB Fat Probe", 35),
    ("TLS 1.2", 36),
    ("TLS 1.3", 37),
    ("HTTP Injection", 38),
    ("Proxy Xray Connectivity (домен", 40),
    ("Proxy Xray Connectivity (domain", 40),
    ("Proxy Xray Connectivity (IP", 41),
    ("Proxy Xray Connectivity", 42),
    ("Proxy Xray Test", 45),
    ("Proxy Exit IP", 50),
    ("Proxy SNI", 60),
    ("Proxy TCP Tunnel", 70),
    ("Proxy Tunnel", 71),
    ("Target via Proxy", 80),
    ("Xray Cross-Proxy Connectivity", 82),
    ("Censor Canary", 85),
    ("Telegram Reachability", 86),
    ("RKN", 90),
    ("SNI Brute Force", 95),
]


def _check_sort_key(result: DiagnosticResult) -> tuple[int, str]:
    """Sort key for ordering checks within a host block."""
    name = result.check_name
    for prefix, rank in _CHECK_ORDER:
        if name.startswith(prefix):
            return (rank, name)
    return (1000, name)


def _short_check_name(name: str) -> str:
    """Strip noisy suffixes from a check name for table rendering."""
    # Shorten "(домен: X)" / "(domain: X)" → "(домен)" / "(domain)",
    # "(IP: X)" → "(IP)" — host is already in the section header.
    name = re.sub(r"\s*\((домен|domain):[^)]+\)", "", name)
    name = re.sub(r"\s*\(IP:[^)]+\)", " (IP)", name)
    # "Proxy Xray Connectivity" → "Proxy Connectivity" (the "Xray" qualifier
    # is implied since this is the analyze command).
    name = name.replace("Xray Cross-Proxy Connectivity", "Cross-Proxy Check")
    name = name.replace("Proxy Xray Connectivity", "Proxy Connectivity")
    name = name.replace("Proxy Xray Test", "Proxy Test")
    name = name.replace("Proxy Exit IP (Xray)", "Exit IP")
    name = name.replace("Proxy SNI Connection (Xray)", "SNI Reachability")
    name = name.replace("DNS Resolution (Check-Host)", "DNS")
    name = name.replace("TCP Connection", "TCP Connect")
    name = name.replace("TCP 16-20 KB Fat Probe", "DPI Fat Probe")
    name = name.replace("Telegram Reachability", "Telegram")
    name = name.replace("Censor Canary", "Censor Check")
    name = name.replace("SNI Brute Force", "SNI Brute")
    return name


def _check_detail_text(result: DiagnosticResult) -> str:
    """Pick the most useful single-line detail for a check result."""
    msg = (result.message or "").strip()
    details = result.details

    if result.status == CheckStatus.PASS:
        bits: list[str] = []
        if "exit_ip" in details:
            bits.append(f"exit {details['exit_ip']}")
        if "latency_avg_ms" in details and "TCP Ping" in result.check_name:
            bits.append(f"avg {details['latency_avg_ms']}ms")
        if "http_status" in details and "HTTP" not in (msg or ""):
            bits.append(f"HTTP {details['http_status']}")
        return " · ".join(bits) if bits else ""

    # For DPI Fat Probe failures, prefer the compact label over the verbose
    # aiohttp error string (e.g. "tls_dpi" instead of "Cannot connect to
    # host X ssl:default [[SSL: TLSV1_ALERT_...").
    if "Fat Probe" in result.check_name and result.status == CheckStatus.FAIL:
        label = details.get("label", "")
        if label:
            return label

    # FAIL / WARN / TIMEOUT / SKIP — keep the message
    return msg


def _problem_fingerprint(diag: HostDiagnostic) -> tuple:
    """Stable signature for "this host has the same problem as another".

    Built from the (canonical check name, status) pairs. Two hosts that both
    have ✓ DNS / ⏱ TCP Connect / ✓ Proxy Connectivity / ✓ Exit IP / ✓ SNI
    will share a fingerprint regardless of which specific server they hit.
    """
    return tuple(sorted((_short_check_name(r.check_name), str(r.status)) for r in diag.results))


def _normalize_recommendation(rec: str, host_label: str) -> str:
    """Replace the host's own server:port inside a recommendation with a placeholder.

    Lets us deduplicate "X.com:443 reachable via Y" / "Z.com:443 reachable via Y"
    into a single shared recommendation when they're otherwise identical.
    """
    # Extract the bare server:port from "Name (server:port)"
    m = re.search(r"\(([^()]+:\d+)\)\s*$", host_label)
    if m:
        rec = rec.replace(m.group(1), "<host>")
    return rec


def _build_host_table(diag: HostDiagnostic) -> Table:
    """Render a per-host check breakdown as a compact Rich table."""
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        pad_edge=False,
    )
    table.add_column("Status", justify="center", width=2, no_wrap=True)
    table.add_column("Check", style="bold", min_width=18, no_wrap=True)
    table.add_column("Detail", style="dim", overflow="fold")

    for result in sorted(diag.results, key=_check_sort_key):
        icon, color = _status_icon_and_color(result.status)
        table.add_row(
            f"[{color}]{icon}[/{color}]",
            _short_check_name(result.check_name),
            _check_detail_text(result),
        )
    return table


def _compact_recommendations(recs: list[str]) -> list[str]:
    """Trim noisy recommendation blocks.

    Drops the verbose "Solutions:\\n  1) ...\\n  2) ..." multi-line strings
    emitted by standalone_analyzer — those repeat near-identical boilerplate
    on every problem host. Keeps single-line recs as-is.
    """
    out: list[str] = []
    for rec in recs:
        if rec.startswith("Solutions:"):
            continue
        # Collapse remaining multi-line recs into the first line only.
        first_line = rec.splitlines()[0].strip()
        if first_line:
            out.append(first_line)
    return out


def _print_censor_check_results(summary) -> None:
    """Print censor-check final summary panel and details for problematic domains."""
    blocked = [r for r in summary.results if r.status == DomainStatus.BLOCKED]
    partial = [r for r in summary.results if r.status == DomainStatus.PARTIAL]

    border = "red" if summary.blocked else ("yellow" if summary.partial else "green")
    status_icon = "✗" if summary.blocked else ("⚠" if summary.partial else "✓")

    summary_lines = [
        f"{status_icon}  [bold]{summary.total}[/bold] domains checked"
        f"  ·  [green]{summary.ok} OK[/green]"
        f"  ·  [red]{summary.blocked} blocked[/red]"
        f"  ·  [yellow]{summary.partial} partial[/yellow]"
        f"  ·  [dim]{summary.duration_seconds:.1f}s[/dim]",
    ]
    if summary.proxy_url:
        summary_lines.append(f"[dim]via {summary.proxy_url}[/dim]")
    else:
        summary_lines.append("[dim]direct connection[/dim]")

    console.print()
    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold]Censor-Check — Summary[/bold]",
            border_style=border,
            padding=(0, 2),
        )
    )
    console.print()

    if not summary.results:
        return

    # BLOCKED domains — show details (IPs, stub, block type)
    if blocked:
        console.print(f"[bold red]✗  Blocked ({len(blocked)})[/bold red]\n")
        table = Table(show_header=True, box=None, padding=(0, 2), header_style="dim")
        table.add_column("Domain", style="bold red", min_width=26)
        table.add_column("Reason", style="red")
        table.add_column("Details", style="dim")

        for result in blocked:
            details_parts = []
            if result.ips:
                details_parts.append(", ".join(result.ips[:2]))
            if result.details.get("rkn_stub_ip"):
                details_parts.append(f"stub:{result.details['rkn_stub_ip']}")
            table.add_row(
                result.domain,
                result.block_type or "BLOCKED",
                "  ".join(details_parts),
            )
        console.print(table)
        console.print()

    # PARTIAL domains — show HTTP/TLS details
    if partial:
        console.print(f"[bold yellow]⚠  Partial ({len(partial)})[/bold yellow]\n")
        table = Table(show_header=True, box=None, padding=(0, 2), header_style="dim")
        table.add_column("Domain", style="bold yellow", min_width=26)
        table.add_column("Reason", style="yellow")
        table.add_column("HTTP", justify="center", style="dim")
        table.add_column("HTTPS", justify="center", style="dim")
        table.add_column("TLS", justify="center", style="dim")

        for result in partial:
            table.add_row(
                result.domain,
                result.block_type or "PARTIAL",
                str(result.http_code) if result.http_code else "–",
                str(result.https_code) if result.https_code else "–",
                "[green]✓[/green]" if result.tls_valid else "[red]✗[/red]",
            )
        console.print(table)
        console.print()


def main() -> None:
    """Main entry point."""
    setup_logging()

    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "analyze":
        exit_code = asyncio.run(cmd_analyze(args))
        sys.exit(exit_code)
    elif args.command == "check":
        exit_code = asyncio.run(cmd_check(args))
        sys.exit(exit_code)
    elif args.command == "scan":
        exit_code = asyncio.run(cmd_scan(args))
        sys.exit(exit_code)
    elif args.command == "serve":
        exit_code = asyncio.run(cmd_serve(args))
        sys.exit(exit_code)
    elif args.command == "dpi":
        exit_code = asyncio.run(cli_dpi.dispatch(args))
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
