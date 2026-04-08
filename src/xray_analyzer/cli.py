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
from xray_analyzer.core.models import CheckStatus, HostDiagnostic
from xray_analyzer.core.xray_client import XrayCheckerClient

log = get_logger("cli")
console = Console()


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
            console.print("[yellow]Starting continuous monitoring... (Ctrl+C to stop)[/yellow]")
            while True:
                diagnostics = await analyzer.run_full_analysis()
                _print_analysis_results(diagnostics)
                console.print(f"\n[dim]Next check in {settings.check_interval_seconds}s...[/dim]")
                await asyncio.sleep(settings.check_interval_seconds)
        else:
            console.print("[bold blue]Starting Xray Analyzer diagnostics...[/bold blue]\n")
            diagnostics = await analyzer.run_full_analysis()
            _print_analysis_results(diagnostics)

        return 0
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
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
        console.print(f"[bold red]Error: {e}[/bold red]")
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
        console.print(f"[bold red]Error: {e}[/bold red]")
        return 1
    finally:
        await client.close()


def _print_analysis_results(diagnostics: list[HostDiagnostic]) -> None:
    """Print full analysis results table."""
    if not diagnostics:
        console.print("[yellow]No proxies to analyze[/yellow]")
        return

    # Summary
    problematic = [d for d in diagnostics if d.overall_status != CheckStatus.PASS]
    console.print(f"[bold]Анализ завершен:[/bold] {len(diagnostics)} хостов, "
                  f"[red]{len(problematic)} с проблемами[/red]\n")

    # Build table
    table = Table(title="Diagnostic Results")
    table.add_column("Host", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Checks", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Recommendations", style="yellow")

    for diag in diagnostics:
        failed = [r for r in diag.results if r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)]
        status_text = (
            "[green]✓ PASS[/green]"
            if diag.overall_status == CheckStatus.PASS
            else "[red]✗ FAIL[/red]"
        )

        table.add_row(
            diag.host,
            status_text,
            str(len(diag.results)),
            f"[red]{len(failed)}[/red]" if failed else "0",
            "\n".join(f"• {r}" for r in diag.recommendations[:2]) if diag.recommendations else "-",
        )

    console.print(table)

    # Detailed recommendations for problematic
    if problematic:
        console.print("\n[bold red]Рекомендации по исправлению:[/bold red]\n")
        for diag in problematic:
            console.print(f"[cyan]{diag.host}:[/cyan]")
            for rec in diag.recommendations:
                console.print(f"  → {rec}")
            # Also show check-specific recommendations
            for result in diag.results:
                if result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT):
                    recs = result.details.get("recommendations", [])
                    for rec in recs[:2]:
                        console.print(f"    [{result.check_name}] {rec}")
            console.print()


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
