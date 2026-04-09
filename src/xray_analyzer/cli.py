"""CLI interface for xray-analyzer using argparse and rich."""

import argparse
import asyncio
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from xray_analyzer.core.analyzer import XrayAnalyzer
from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger, setup_logging
from xray_analyzer.core.models import CheckSeverity, CheckStatus, HostDiagnostic
from xray_analyzer.core.xray_client import XrayCheckerClient

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

    # check command
    check_parser = subparsers.add_parser("check", help="Check a single host")
    check_parser.add_argument("host", help="Host to check")
    check_parser.add_argument("--port", type=int, default=443, help="Port to check (default: 443)")

    # status command
    subparsers.add_parser("status", help="Show checker API status")

    return parser


async def cmd_analyze(watch: bool = False) -> int:
    """Run full analysis command."""
    analyzer = XrayAnalyzer()

    try:
        if watch:
            error_console.print("[yellow]Starting continuous monitoring... (Ctrl+C to stop)[/yellow]")
            while True:
                diagnostics = await analyzer.run_full_analysis()
                _print_analysis_results(diagnostics)
                error_console.print(f"\n[dim]Next check in {settings.check_interval_seconds}s...[/dim]")
                await asyncio.sleep(settings.check_interval_seconds)
        else:
            diagnostics = await analyzer.run_full_analysis()
            _print_analysis_results(diagnostics)

        return 0
    except Exception as e:
        error_console.print(f"[bold red]Error: {e}[/bold red]")
        log.error("Analysis failed", error=str(e))
        return 1
    finally:
        await analyzer.close()


async def cmd_check(host: str, port: int) -> int:
    """Run single host check command."""
    console.print(f"[bold blue]Checking {host}:{port}...[/bold blue]\n")

    analyzer = XrayAnalyzer()
    try:
        diagnostic = await analyzer.run_single_host_analysis(host, port)
        _print_single_diagnostic(diagnostic)
        return 0 if diagnostic.overall_status == CheckStatus.PASS else 1
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


def _print_analysis_results(diagnostics: list[HostDiagnostic]) -> None:
    """Print full analysis results with detailed check-by-check breakdown."""
    if not diagnostics:
        console.print("[yellow]No proxies to analyze[/yellow]")
        return

    # Filter out skipped virtual hosts (no results means host was skipped)
    real_diagnostics = [d for d in diagnostics if d.results]
    virtual_hosts = [d for d in diagnostics if not d.results]

    if virtual_hosts:
        for vh in virtual_hosts:
            host_name = vh.host.split(":")[0]
            console.print(f"[dim]○ Пропущен виртуальный хост: {host_name}[/dim]")

    if not real_diagnostics:
        console.print("[yellow]No real hosts to analyze (only virtual/skipped hosts)[/yellow]")
        return

    # Separate into passing and failing hosts
    passing = [d for d in real_diagnostics if d.overall_status == CheckStatus.PASS]
    failing = [d for d in real_diagnostics if d.overall_status != CheckStatus.PASS]

    # === SUMMARY HEADER ===
    console.print()
    console.print(
        Panel(
            f"[bold]Всего хостов:[/bold] {len(real_diagnostics)}  |  "
            f"[green]✓ OK:[/green] {len(passing)}  |  "
            f"[red]✗ PROBLEMS:[/red] {len(failing)}",
            title="[bold blue]Результат анализа[/bold blue]",
            border_style="green" if not failing else "red",
        )
    )
    console.print()

    # === PROBLEM HOSTS (detailed) ===
    if failing:
        console.print("[bold red]⚠ ХОСТЫ С ПРОБЛЕМАМИ[/bold red]\n")

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
                console.print("    [bold yellow]Что делать:[/bold yellow]")
                for rec in diag.recommendations:
                    console.print(f"      → {rec}")

            console.print()

    # === PASSING HOSTS (compact) ===
    if passing:
        console.print("[bold green]✓ ХОСТЫ БЕЗ ПРОБЛЕМ[/bold green]\n")

        table = Table(show_header=True, box=None, padding=(0, 2))
        table.add_column("Host", style="cyan")
        table.add_column("DNS", justify="center")
        table.add_column("TCP", justify="center")
        table.add_column("Ping", justify="center")
        table.add_column("RKN", justify="center")
        table.add_column("Proxy", justify="center")

        for diag in passing:
            dns = _check_status_icon(diag, "DNS")
            tcp = _check_status_icon(diag, "TCP Connection")
            ping = _check_status_icon(diag, "TCP Ping")
            rkn = _check_status_icon(diag, "RKN")
            proxy = _check_status_icon(diag, "Xray Connectivity") or _check_status_icon(diag, "Tunnel")

            table.add_row(
                diag.host,
                dns,
                tcp,
                ping,
                rkn,
                proxy,
            )

        console.print(table)
        console.print()

    # === DETAILED CHECK RESULTS FOR ALL HOSTS ===
    # Only show for problem hosts — passing hosts are already summarized
    problem_hosts_only = [d for d in real_diagnostics if d.overall_status != CheckStatus.PASS]

    if problem_hosts_only:
        console.print("[bold]Подробные результаты:[/bold]\n")

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

            # Skipped checks — compact
            for result in skipped:
                reason = result.message[:60] if result.message else "пропущено"
                console.print(f"    [dim]○ SKIP  {result.check_name}: {reason}[/dim]")

            # Passed checks — compact with key details
            for result in passed:
                icon, color = _status_icon_and_color(result.status)
                console.print(f"    [{color}]{icon}[/{color}] {result.check_name}")
                details = result.details
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
                    console.print(f"       [dim]Через прокси: {details['working_proxy']}[/dim]")
                    if "duration_ms" in details:
                        console.print(f"       [dim]Время: {details['duration_ms']}ms[/dim]")

            console.print()


def _check_status_icon(diagnostic: HostDiagnostic, check_name_part: str) -> str:
    """Get a compact status icon for a check."""
    for result in diagnostic.results:
        if check_name_part.lower() in result.check_name.lower():
            if result.status == CheckStatus.PASS:
                return "[green]✓[/green]"
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
        CheckStatus.FAIL: ("✗", "red"),
        CheckStatus.TIMEOUT: ("⏱", "yellow"),
        CheckStatus.SKIP: ("○", "dim"),
    }.get(status, ("?", "white"))


def _print_single_diagnostic(diagnostic: HostDiagnostic) -> None:
    """Print detailed diagnostic for a single host."""
    status_emoji = "✓" if diagnostic.overall_status == CheckStatus.PASS else "✗"
    status_color = "green" if diagnostic.overall_status == CheckStatus.PASS else "red"

    console.print(
        Panel(
            Text(f"{status_emoji} {diagnostic.host}", style=f"bold {status_color}"),
            subtitle=f"Status: {diagnostic.overall_status.value.upper()}",
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
        exit_code = asyncio.run(cmd_analyze(watch=args.watch))
        sys.exit(exit_code)
    elif args.command == "check":
        exit_code = asyncio.run(cmd_check(args.host, args.port))
        sys.exit(exit_code)
    elif args.command == "status":
        exit_code = asyncio.run(cmd_status())
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
