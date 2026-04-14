"""CLI interface for xray-analyzer using argparse and rich."""

import argparse
import asyncio
import re
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from rich.console import Console
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

from xray_analyzer.core.analyzer import XrayAnalyzer
from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger, setup_logging
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult, HostDiagnostic
from xray_analyzer.core.standalone_analyzer import _is_valid_server_address, analyze_subscription_proxies
from xray_analyzer.core.xray_client import XrayCheckerClient
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
from xray_analyzer.diagnostics.subscription_parser import fetch_subscription, parse_share_url
from xray_analyzer.diagnostics.xray_downloader import ensure_xray
from xray_analyzer.diagnostics.xray_manager import XrayInstance
from xray_analyzer.metrics.server import MetricsState, run_metrics_server

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


_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


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
        "--watch",
        action="store_true",
        help="Continuously monitor proxies at configured interval",
    )
    # Standalone mode options (run without .env configuration)
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
        "--checker-api-url",
        type=str,
        help="Xray Checker API URL (overrides CHECKER_API_URL)",
    )
    analyze_parser.add_argument(
        "--checker-api-username",
        type=str,
        help="Basic auth username (overrides CHECKER_API_USERNAME)",
    )
    analyze_parser.add_argument(
        "--checker-api-password",
        type=str,
        help="Basic auth password (overrides CHECKER_API_PASSWORD)",
    )
    analyze_parser.add_argument(
        "--analyze-online",
        action="store_true",
        help="Analyze all proxies including online ones (overrides ANALYZE_ONLINE_PROXIES)",
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

    # status command
    subparsers.add_parser("status", help="Show xray-checker API status")

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
    if getattr(args, "analyze_online", False):
        settings.analyze_online_proxies = True
    if getattr(args, "checker_api_url", None):
        settings.checker_api_url = args.checker_api_url
    if getattr(args, "checker_api_username", None):
        settings.checker_api_username = args.checker_api_username
    if getattr(args, "checker_api_password", None):
        settings.checker_api_password = args.checker_api_password

    # Determine if we're running in standalone mode (subscription URL only, no checker API)
    is_standalone = (
        settings.subscription_url and not settings.checker_api_username and not settings.checker_api_password
    )

    if is_standalone:
        return await _run_standalone_analysis()
    else:
        return await _run_full_analysis_with_checker(args.watch)


async def _run_standalone_analysis() -> int:
    """Run analysis using only subscription URL without checker API."""
    console.print("[bold blue]Running in standalone mode (subscription only, no checker API)[/bold blue]\n")

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

        # Fetch subscription proxies
        with console.status("[dim]Fetching subscription...[/dim]", spinner="dots"):
            shares = await fetch_subscription(
                settings.subscription_url,
                hwid=settings.subscription_hwid,
            )
        console.print(f"[green]✓[/green] Loaded [bold]{len(shares)}[/bold] proxies from subscription\n")

        if not shares:
            console.print("[yellow]No proxies found in subscription[/yellow]")
            return 0

        # Run diagnostics on all proxies
        console.print(f"[bold]Testing {len(shares)} proxies...[/bold]\n")
        with console.status(f"[dim]Running diagnostics on {len(shares)} proxies...[/dim]", spinner="dots"):
            diagnostics = await analyze_subscription_proxies(shares)
        _print_analysis_results(diagnostics)
        return 0

    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        log.error("Standalone analysis failed", error=str(e))
        return 1


async def _run_full_analysis_with_checker(watch: bool = False) -> int:
    """Run analysis with checker API."""
    analyzer = XrayAnalyzer()

    try:
        if watch:
            console.print("[yellow]Starting continuous monitoring... (Ctrl+C to stop)[/yellow]")
            while True:
                with console.status("[dim]Fetching proxies and running diagnostics...[/dim]", spinner="dots"):
                    diagnostics = await analyzer.run_full_analysis()
                _print_analysis_results(diagnostics)
                console.print(f"\n[dim]Next check in {settings.check_interval_seconds}s...[/dim]")
                await asyncio.sleep(settings.check_interval_seconds)
        else:
            with console.status("[dim]Fetching proxies and running diagnostics...[/dim]", spinner="dots"):
                diagnostics = await analyzer.run_full_analysis()
            _print_analysis_results(diagnostics)

        return 0
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        log.error("Analysis failed", error=str(e))
        return 1
    finally:
        await analyzer.close()


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
                    proxy_url=proxy_url,
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
            error_console.print("[bold red]✗ Xray binary not found — required for subscription proxy testing[/bold red]")  # noqa: E501
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
                        proxy_url=proxy_url,
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
                    proxy_url=proxy_url,
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
        console.print(
            f"[green]✓[/green] Loaded [bold]{len(sub_shares)}[/bold] proxies from subscription"
        )

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
        console.print(
            f"[green]✓[/green] Listening on [bold]http://{host}:{port}/metrics[/bold]  (Ctrl+C to stop)\n"
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

                        async def _scan_one_proxy(
                            share, _sem=sem, _prog=progress, _tid=task_id
                        ) -> None:
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
                                        log.warning("Proxy host unreachable, skipping scan", proxy=label, error=str(tcp_err))
                                        _prog.console.print(
                                            f"  [yellow]⚠[/yellow] [bold]{label}[/bold]  [dim]host unreachable — scan skipped[/dim]"
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
                                    _prog.console.print(
                                        f"  [red]✗[/red] [bold]{label}[/bold]  [dim]{e}[/dim]"
                                    )
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
        except (asyncio.CancelledError, KeyboardInterrupt):
            console.print("\n[dim]Shutting down...[/dim]")
        finally:
            await runner.cleanup()

        return 0
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        return 1


async def cmd_status() -> int:
    """Show checker API status command."""
    client = XrayCheckerClient()
    try:
        # Health check
        health = await client.check_health()
        console.print(f"Health: {'[green]OK[/green]' if health else '[red]FAIL[/red]'}")

        if not health:
            return 1

        # System info
        try:
            sys_info = await client.get_system_info()
            info = sys_info.data
            console.print("\n[b]System Information:[/b]")
            console.print(f"  Version: {info.version}")
            console.print(f"  Instance: {info.instance}")
            console.print(f"  Uptime: {info.uptime}")
        except Exception as e:
            console.print(f"[dim]Failed to get system info: {e}[/dim]")

        # Status summary
        try:
            summary_resp = await client.get_status_summary()
            summary = summary_resp.data
            console.print("\n[b]Proxy Status Summary:[/b]")
            console.print(f"  Total: {summary.total}")
            console.print(f"  Online: [green]{summary.online}[/green]")
            console.print(f"  Offline: [red]{summary.offline}[/red]")
            console.print(f"  Avg Latency: {summary.avg_latency_ms}ms")
        except Exception as e:
            console.print(f"[dim]Failed to get status summary: {e}[/dim]")

        # Server IP
        try:
            ip_resp = await client.get_system_ip()
            console.print(f"\n[b]Server IP:[/b] {ip_resp.data.get('ip', 'N/A')}")
        except Exception as e:
            console.print(f"[dim]Failed to get server IP: {e}[/dim]")

        return 0
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        return 1
    finally:
        await client.close()


def _print_analysis_results(diagnostics: list[HostDiagnostic]) -> None:
    """Print full analysis results with detailed check-by-check breakdown."""
    if not diagnostics:
        console.print("[yellow]No proxies to analyze[/yellow]")
        return

    # Filter out skipped virtual/invalid hosts (no results means host was skipped)
    real_diagnostics = [d for d in diagnostics if d.results]
    skipped_hosts = [d for d in diagnostics if not d.results]

    if skipped_hosts:
        for sh in skipped_hosts:
            console.print(f"[dim]○ Skipped: {sh.host}[/dim]")

    if not real_diagnostics:
        console.print("[yellow]No real hosts to analyze (only virtual/skipped hosts)[/yellow]")
        return

    # Separate into passing, warn, and failing hosts
    passing = [d for d in real_diagnostics if d.overall_status == CheckStatus.PASS]
    warning = [d for d in real_diagnostics if d.overall_status == CheckStatus.WARN]
    failing = [d for d in real_diagnostics if d.overall_status not in (CheckStatus.PASS, CheckStatus.WARN)]

    # === SUMMARY HEADER ===
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
    console.print()

    # WARN hosts go into the passing compact table (they work with caveats)
    passing_and_warn = passing + warning

    # === PROBLEM HOSTS (detailed) ===
    if failing:
        console.print("[bold red]⚠ HOSTS WITH PROBLEMS[/bold red]\n")

        for diag in failing:
            failed_checks = [r for r in diag.results if r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)]
            warn_checks = [r for r in diag.results if r.severity == CheckSeverity.WARNING]

            console.print(f"  [bold cyan]→ {diag.host}[/bold cyan]")
            console.print(f"  [dim]{'─' * 60}[/dim]")

            # Print failed/timeout checks first
            for result in failed_checks:
                severity_icon = {
                    CheckStatus.FAIL: "[red]✗ FAIL[/red]",
                    CheckStatus.TIMEOUT: "[yellow]⏱ TIMEOUT[/yellow]",
                }.get(result.status, "?")

                console.print(f"    {severity_icon} [bold]{result.check_name}[/bold]")
                console.print(f"      {result.message}")

                # Show key details
                details = result.details
                if "local_ips" in details:
                    local_ips = details.get("local_ips", ["N/A"]) or ["N/A"]
                    ch_ips = details.get("checkhost_ips", ["N/A"]) or ["N/A"]
                    console.print(f"      [dim]Local DNS:[/dim] {', '.join(local_ips)}")
                    console.print(f"      [dim]Check-Host:[/dim] {', '.join(ch_ips)}")
                if "exit_ip" in details:
                    console.print(f"      [dim]Exit IP:[/dim] {details['exit_ip']}")
                if "http_status" in details:
                    console.print(f"      [dim]HTTP:[/dim] {details['http_status']}")

            # Print warnings
            for result in warn_checks:
                console.print(f"    [yellow]⚠ WARNING[/yellow] [bold]{result.check_name}[/bold]")
                console.print(f"      {result.message}")

            # Print recommendations
            if diag.recommendations:
                console.print("    [bold yellow]What to do:[/bold yellow]")
                for rec in diag.recommendations:
                    console.print(f"      → {rec}")

            console.print()

    # === PASSING + WARN HOSTS (compact) ===
    if passing_and_warn:
        console.print("[bold green]✓ HOSTS WITHOUT ISSUES[/bold green]\n")

        table = Table(show_header=True, box=None, padding=(0, 2))
        table.add_column("Host", style="cyan")
        table.add_column("DNS", justify="center")
        table.add_column("TCP", justify="center")
        table.add_column("Ping", justify="center")
        table.add_column("RKN Thr", justify="center")
        table.add_column("Proxy", justify="center")

        for diag in passing_and_warn:
            dns = _check_status_icon(diag, "DNS")
            tcp = _check_status_icon(diag, "TCP Connection")
            ping = _check_status_icon(diag, "TCP Ping")
            rkn_thr = _check_status_icon(diag, "RKN Throttle")
            proxy = _check_status_icon(diag, "Xray Connectivity") or _check_status_icon(diag, "Tunnel")

            table.add_row(
                diag.host,
                dns,
                tcp,
                ping,
                rkn_thr,
                proxy,
            )

        console.print(table)
        console.print()

    # === DETAILED CHECK RESULTS FOR ALL HOSTS ===
    # Only show for problem hosts — passing/warn hosts are already summarized
    problem_hosts_only = [d for d in real_diagnostics if d.overall_status not in (CheckStatus.PASS, CheckStatus.WARN)]

    if problem_hosts_only:
        console.print("[bold]Detailed results:[/bold]\n")

        for diag in problem_hosts_only:
            status_color = "green" if diag.overall_status == CheckStatus.PASS else "red"
            console.print(f"  [bold {status_color}]{diag.host}[/bold {status_color}]")
            console.print(f"  [dim]{'─' * 60}[/dim]")

            # Separate into pass/fail/skip for better readability
            failed = [r for r in diag.results if r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)]
            skipped = [r for r in diag.results if r.status == CheckStatus.SKIP]
            passed = [r for r in diag.results if r.status == CheckStatus.PASS]

            # Failed checks with details
            for result in failed:
                icon, color = _status_icon_and_color(result.status)
                console.print(f"    [{color}]{icon}[/{color}] [bold]{result.check_name}[/bold]")
                console.print(f"       {result.message}")
                details = result.details
                if "total_bytes_received" in details:
                    bytes_val = details["total_bytes_received"]
                    kb_val = bytes_val / 1024
                    console.print(f"       [dim]Received: {bytes_val} bytes ({kb_val:.1f}KB)[/dim]")
                if "http_status" in details:
                    console.print(f"       [dim]HTTP: {details['http_status']}[/dim]")
                if "exit_ip" in details:
                    console.print(f"       [dim]Exit IP: {details['exit_ip']}[/dim]")
                if "local_ips" in details:
                    console.print(f"       [dim]DNS IPs: {', '.join(details['local_ips'][:2])}[/dim]")
                if "checkhost_ips" in details:
                    console.print(f"       [dim]Check-Host IPs: {', '.join(details['checkhost_ips'][:2])}[/dim]")
                if "latency_avg_ms" in details:
                    avg = details["latency_avg_ms"]
                    mn = details["latency_min_ms"]
                    mx = details["latency_max_ms"]
                    console.print(f"       [dim]Latency: avg={avg}ms, min={mn}ms, max={mx}ms[/dim]")
                if "packet_loss_pct" in details:
                    console.print(f"       [dim]Loss: {details['packet_loss_pct']}%[/dim]")
                if "sni_domain" in details:
                    console.print(f"       [dim]SNI domain: {details['sni_domain']}[/dim]")
                if "checked_for_proxy" in details:
                    console.print(f"       [dim]Check for proxy: {details['checked_for_proxy']}[/dim]")

            # Skipped checks — compact
            for result in skipped:
                reason = result.message[:60] if result.message else "skipped"
                console.print(f"    [dim]○ SKIP  {result.check_name}: {reason}[/dim]")

            # Passed checks — compact with key details
            for result in passed:
                icon, color = _status_icon_and_color(result.status)
                console.print(f"    [{color}]{icon}[/{color}] {result.check_name}")
                details = result.details
                if "total_bytes_received" in details:
                    bytes_val = details["total_bytes_received"]
                    kb_val = bytes_val / 1024
                    console.print(f"       [dim]Received: {bytes_val} bytes ({kb_val:.1f}KB)[/dim]")
                if "common_ips" in details:
                    console.print(f"       [dim]Match Check-Host: {', '.join(details['common_ips'])}[/dim]")
                if "latency_avg_ms" in details:
                    avg = details["latency_avg_ms"]
                    mn = details["latency_min_ms"]
                    mx = details["latency_max_ms"]
                    console.print(f"       [dim]Latency: avg={avg}ms, min={mn}ms, max={mx}ms[/dim]")
                if "packet_loss_pct" in details:
                    console.print(f"       [dim]Loss: {details['packet_loss_pct']}%[/dim]")
                if "exit_ip" in details:
                    console.print(f"       [dim]Exit IP: {details['exit_ip']}[/dim]")
                if "http_status" in details:
                    console.print(f"       [dim]HTTP: {details['http_status']}[/dim]")
                if "working_proxy" in details:
                    console.print(f"       [dim]Via proxy: {details['working_proxy']}[/dim]")
                    if "duration_ms" in details:
                        console.print(f"       [dim]Duration: {details['duration_ms']}ms[/dim]")

            console.print()


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


def _print_single_diagnostic(diagnostic: HostDiagnostic) -> None:
    """Print detailed diagnostic for a single host."""
    if diagnostic.overall_status == CheckStatus.PASS:
        status_emoji, status_color, border_style = "✓", "green", "green"
    elif diagnostic.overall_status == CheckStatus.WARN:
        status_emoji, status_color, border_style = "⚠", "yellow", "yellow"
    else:
        status_emoji, status_color, border_style = "✗", "red", "red"

    console.print(
        Panel(
            Text(f"{status_emoji} {diagnostic.host}", style=f"bold {status_color}"),
            subtitle=f"Status: {diagnostic.overall_status.value.upper()}",
            border_style=border_style,
        )
    )

    # Check results
    table = Table(show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Message", style="white")
    table.add_column("Duration", justify="right")

    for result in diagnostic.results:
        if result.status == CheckStatus.PASS:
            status = "[green]✓ PASS[/green]"
        elif result.status == CheckStatus.WARN:
            status = "[yellow]⚠ WARN[/yellow]"
        elif result.status == CheckStatus.FAIL:
            status = "[red]✗ FAIL[/red]"
        elif result.status == CheckStatus.TIMEOUT:
            status = "[yellow]⏱ TIMEOUT[/yellow]"
        else:
            status = "[dim]○ SKIP[/dim]"

        table.add_row(
            result.check_name,
            status,
            result.message,
            f"{result.duration_ms:.0f}ms",
        )

    console.print(table)

    # Recommendations
    if diagnostic.recommendations:
        console.print("\n[bold yellow]Recommendations:[/bold yellow]")
        for rec in diagnostic.recommendations:
            console.print(f"  → {rec}")


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
    elif args.command == "status":
        exit_code = asyncio.run(cmd_status())
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
