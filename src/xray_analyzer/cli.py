"""CLI interface for xray-analyzer using argparse and rich."""

import argparse
import asyncio
import sys

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
from xray_analyzer.core.models import CheckSeverity, CheckStatus, HostDiagnostic
from xray_analyzer.core.standalone_analyzer import analyze_subscription_proxies
from xray_analyzer.core.xray_client import XrayCheckerClient
from xray_analyzer.diagnostics.censor_checker import (
    DEFAULT_CENSOR_DOMAINS,
    DomainCheckResult,
    DomainStatus,
    fetch_whitelist_domains,
    run_censor_check,
)

log = get_logger("cli")
console = Console()
error_console = Console(stderr=True)


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
        "--rkn-check",
        action="store_true",
        help="Enable RKN blocking checks (overrides RKN_CHECK_ENABLED)",
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

    # check command
    check_parser = subparsers.add_parser("check", help="Check a single host")
    check_parser.add_argument("host", help="Host to check")
    check_parser.add_argument("--port", type=int, default=443, help="Port to check (default: 443)")
    check_parser.add_argument(
        "--proxy",
        help="Proxy URL to route checks through (e.g., socks5://127.0.0.1:1080, http://user:pass@host:port)",
    )

    # status command
    subparsers.add_parser("status", help="Show checker API status")

    # censor-check command
    censor_parser = subparsers.add_parser(
        "censor-check",
        help="Test web resources for censorship/blocking through proxy",
    )
    censor_parser.add_argument(
        "--domains",
        nargs="*",
        help="List of domains to check (overrides --list)",
    )
    censor_parser.add_argument(
        "--list",
        choices=["default", "whitelist"],
        default="default",
        help="Predefined domain list to use: 'default' (built-in list) or 'whitelist' "
             "(Russia mobile internet whitelist from github.com/hxehex/russia-mobile-internet-whitelist)",
    )
    censor_parser.add_argument(
        "--proxy",
        help="Proxy URL to use for checking (e.g., socks5://127.0.0.1:1080)",
    )
    censor_parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout per domain in seconds (default: from config)",
    )
    censor_parser.add_argument(
        "--max-parallel",
        type=int,
        help="Maximum parallel checks (default: from config)",
    )

    return parser


async def cmd_analyze(args: argparse.Namespace) -> int:
    """Run full analysis command."""
    # Apply CLI overrides to settings
    _apply_cli_overrides(args)

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


async def cmd_check(host: str, port: int, proxy_url: str = "") -> int:
    """Run single host check command."""
    console.print(f"[bold blue]Checking {host}:{port}...[/bold blue]\n")
    if proxy_url:
        console.print(f"[dim]Via proxy: {proxy_url}[/dim]\n")

    analyzer = XrayAnalyzer()
    try:
        diagnostic = await analyzer.run_single_host_analysis(host, port, proxy_url=proxy_url)
        _print_single_diagnostic(diagnostic)
        return 0 if diagnostic.overall_status in (CheckStatus.PASS, CheckStatus.WARN) else 1
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        return 1
    finally:
        await analyzer.close()


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


async def cmd_censor_check(
    domains: list[str] | None = None,
    domain_list: str = "default",
    proxy_url: str = "",
    timeout: int | None = None,
    max_parallel: int | None = None,
) -> int:
    """Run censor-check command."""
    # Use config values if not provided via CLI
    if timeout is None:
        timeout = settings.censor_check_timeout
    if max_parallel is None:
        max_parallel = settings.censor_check_max_parallel

    # Parse domains from CLI or config
    if domains is None:
        if settings.censor_check_domains:
            domains = [d.strip() for d in settings.censor_check_domains.split(",") if d.strip()]
        else:
            domains = []  # Will use defaults / list selection below
    elif len(domains) == 1 and "," in domains[0]:
        # Handle comma-separated domains passed as single argument
        domains = [d.strip() for d in domains[0].split(",") if d.strip()]

    # Use proxy from config if not provided via CLI
    if not proxy_url:
        proxy_url = settings.censor_check_proxy_url

    console.print()
    console.print(Panel(
        f"[bold cyan]🌐  Censor Check[/bold cyan]\n"
        f"[dim]{'Via proxy: ' + proxy_url if proxy_url else 'Direct connection (no proxy)'}[/dim]",
        border_style="blue",
        padding=(0, 2),
    ))
    console.print()

    # If no explicit domains given, apply the selected list
    if not domains:
        if domain_list == "whitelist":
            with console.status("[dim]Fetching Russia mobile internet whitelist...[/dim]", spinner="dots"):
                domains = await fetch_whitelist_domains()
            if not domains:
                error_console.print("[bold red]✗[/bold red] Failed to fetch whitelist — falling back to default list")
                domains = None  # run_censor_check will use DEFAULT_CENSOR_DOMAINS
            else:
                console.print(f"[green]✓[/green] Loaded [bold]{len(domains)}[/bold] domains from whitelist")
                console.print()
        else:
            domains = None  # run_censor_check will use DEFAULT_CENSOR_DOMAINS

    domain_count = len(domains) if domains else len(DEFAULT_CENSOR_DOMAINS)

    try:
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
                f"[cyan]Checking {domain_count} domains[/cyan]",
                total=domain_count,
            )

            def on_domain_complete(result: DomainCheckResult) -> None:
                if result.status == DomainStatus.OK:
                    icon = "[green]✓[/green]"
                    label = "[green]OK[/green]     "
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
                progress.console.print(
                    f"  {icon} [bold]{result.domain:<26}[/bold]{label}{extras_str}"
                )
                progress.advance(task_id)

            summary = await run_censor_check(
                domains=domains,
                proxy_url=proxy_url,
                timeout=timeout,
                max_parallel=max_parallel,
                on_domain_complete=on_domain_complete,
            )

        _print_censor_check_results(summary)

        # Return non-zero if there are blocked domains
        return 1 if summary.blocked > 0 else 0
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        log.error("Censor-check failed", error=str(e))
        return 1


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
        table.add_column("RKN", justify="center")
        table.add_column("RKN Thr", justify="center")
        table.add_column("Proxy", justify="center")

        for diag in passing_and_warn:
            dns = _check_status_icon(diag, "DNS")
            tcp = _check_status_icon(diag, "TCP Connection")
            ping = _check_status_icon(diag, "TCP Ping")
            rkn = _check_status_icon(diag, "RKN")
            rkn_thr = _check_status_icon(diag, "RKN Throttle")
            proxy = _check_status_icon(diag, "Xray Connectivity") or _check_status_icon(diag, "Tunnel")

            table.add_row(
                diag.host,
                dns,
                tcp,
                ping,
                rkn,
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
    console.print(Panel(
        "\n".join(summary_lines),
        title="[bold]Censor-Check — Summary[/bold]",
        border_style=border,
        padding=(0, 2),
    ))
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
        exit_code = asyncio.run(cmd_check(args.host, args.port, proxy_url=args.proxy or ""))
        sys.exit(exit_code)
    elif args.command == "status":
        exit_code = asyncio.run(cmd_status())
        sys.exit(exit_code)
    elif args.command == "censor-check":
        exit_code = asyncio.run(
            cmd_censor_check(
                domains=args.domains,
                domain_list=args.list,
                proxy_url=args.proxy,
                timeout=args.timeout,
                max_parallel=args.max_parallel,
            )
        )
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
