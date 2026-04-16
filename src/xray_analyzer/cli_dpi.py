"""`xray-analyzer dpi ...` subcommand group.

Wires every new Tier 1-6 probe up to a CLI entry point. Kept in its own file
so the main `cli.py` stays legible while we iterate on these.
"""

from __future__ import annotations

import argparse
import asyncio

from rich.console import Console
from rich.table import Table

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.diagnostics.cdn_target_scanner import load_targets, scan_targets
from xray_analyzer.diagnostics.dns_dpi_prober import probe_dns_integrity
from xray_analyzer.diagnostics.fat_probe_checker import check_fat_probe
from xray_analyzer.diagnostics.sni_brute_force_checker import find_working_sni
from xray_analyzer.diagnostics.sni_brute_force_checker import to_diagnostic as sni_to_diag
from xray_analyzer.diagnostics.telegram_checker import check_telegram
from xray_analyzer.diagnostics.telegram_checker import to_diagnostic as tg_to_diag

log = get_logger("cli_dpi")
console = Console()


# ── Subparser registration ──────────────────────────────────────────────────


def register(subparsers: argparse._SubParsersAction) -> None:
    """Attach the `dpi` subcommand tree to the given argparse group."""
    dpi_parser = subparsers.add_parser(
        "dpi",
        help="DPI / censorship deep-diagnostic probes (dns, tcp16, cdn-scan, sni-brute, telegram)",
    )
    dpi_sub = dpi_parser.add_subparsers(dest="dpi_command", help="DPI subcommand")

    # dpi dns
    dns = dpi_sub.add_parser("dns", help="DNS integrity: direct UDP vs DoH + stub-IP harvest")
    dns.add_argument("domains", nargs="+", help="Domain(s) to probe")
    dns.add_argument("--timeout", type=float, default=settings.dns_dpi_timeout)
    dns.add_argument("--udp-only", action="store_true")
    dns.add_argument("--doh-only", action="store_true")

    # dpi tcp16
    tcp16 = dpi_sub.add_parser("tcp16", help="Single fat-probe for TCP 16-20 KB throttle")
    tcp16.add_argument("target", help="IP or hostname")
    tcp16.add_argument("--port", type=int, default=443)
    tcp16.add_argument("--sni", type=str, default=None)
    tcp16.add_argument("--iterations", type=int, default=settings.fat_probe_iterations)

    # dpi cdn-scan
    cdn = dpi_sub.add_parser("cdn-scan", help="Bulk scan of CDN/hosting IPs grouped by ASN for TCP 16-20KB")
    cdn.add_argument("--max-parallel", type=int, default=10)
    cdn.add_argument("--limit", type=int, default=0, help="Only scan first N targets (0=all)")

    # dpi sni-brute
    brute = dpi_sub.add_parser("sni-brute", help="Brute-force working SNI from whitelist against a blocked IP:port")
    brute.add_argument("target", help="IP or hostname")
    brute.add_argument("--port", type=int, default=443)
    brute.add_argument("--max", type=int, default=settings.sni_brute_max_candidates)
    brute.add_argument("--early-exit", type=int, default=1)

    # dpi telegram
    tg = dpi_sub.add_parser("telegram", help="Telegram DL / UL / DC reachability")
    tg.add_argument("--via-proxy", type=str, default=None)
    tg.add_argument("--total-timeout", type=float, default=settings.telegram_total_timeout)


# ── Dispatch ────────────────────────────────────────────────────────────────


async def dispatch(args: argparse.Namespace) -> int:
    sub = getattr(args, "dpi_command", None)
    if sub == "dns":
        return await _cmd_dns(args)
    if sub == "tcp16":
        return await _cmd_tcp16(args)
    if sub == "cdn-scan":
        return await _cmd_cdn_scan(args)
    if sub == "sni-brute":
        return await _cmd_sni_brute(args)
    if sub == "telegram":
        return await _cmd_telegram(args)
    console.print("[yellow]Usage: xray-analyzer dpi <dns|tcp16|cdn-scan|sni-brute|telegram> ...[/yellow]")
    return 1


# ── Commands ────────────────────────────────────────────────────────────────


async def _cmd_dns(args: argparse.Namespace) -> int:
    console.print(f"[bold]DNS integrity probe[/bold] — {len(args.domains)} domain(s)")
    report = await probe_dns_integrity(
        args.domains,
        timeout=args.timeout,
        udp_only=args.udp_only,
        doh_only=args.doh_only,
    )

    if report.udp_server:
        console.print(f"  UDP: [cyan]{report.udp_server[0]} ({report.udp_server[1]})[/cyan]")
    if report.doh_server:
        console.print(f"  DoH: [cyan]{report.doh_server[0]} ({report.doh_server[1]})[/cyan]")
    if report.stub_ips:
        console.print(f"  [yellow]Stub IPs harvested:[/yellow] {', '.join(sorted(report.stub_ips))}")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Domain", style="cyan")
    table.add_column("Verdict")
    table.add_column("UDP answer", style="dim")
    table.add_column("DoH answer", style="dim")
    for r in report.results:
        v = r.details["verdict"]
        color = "green" if v == "ok" else "red"
        table.add_row(
            r.details["domain"],
            f"[{color}]{v}[/{color}]",
            _fmt_ans(r.details.get("udp_answer")),
            _fmt_ans(r.details.get("doh_answer")),
        )
    console.print(table)
    return 0 if report.verdict_counts.get("ok", 0) == len(args.domains) else 1


async def _cmd_tcp16(args: argparse.Namespace) -> int:
    console.print(f"[bold]Fat-probe[/bold] {args.target}:{args.port} (SNI={args.sni or '—'})")
    result = await check_fat_probe(
        args.target,
        port=args.port,
        sni=args.sni,
        iterations=args.iterations,
        chunk_size=settings.fat_probe_chunk_size,
        connect_timeout=settings.fat_probe_connect_timeout,
        read_timeout=settings.fat_probe_read_timeout,
    )
    _print_diagnostic(result)
    return 0 if result.details["label"] == "ok" else 1


async def _cmd_cdn_scan(args: argparse.Namespace) -> int:
    targets = load_targets()
    if args.limit > 0:
        targets = targets[: args.limit]
    console.print(f"[bold]CDN scan[/bold] — {len(targets)} targets, parallelism {args.max_parallel}")
    report = await scan_targets(
        targets,
        max_parallel=args.max_parallel,
        iterations=settings.fat_probe_iterations,
        chunk_size=settings.fat_probe_chunk_size,
        connect_timeout=settings.fat_probe_connect_timeout,
        read_timeout=settings.fat_probe_read_timeout,
        default_sni=settings.fat_probe_default_sni,
    )
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Provider", style="cyan")
    table.add_column("ASN")
    table.add_column("OK / Total")
    table.add_column("Blocked")
    table.add_column("Verdict")
    for s in report.summaries:
        color = {"ok": "green", "partial": "yellow", "blocked": "red"}.get(s.verdict, "white")
        table.add_row(
            s.provider,
            f"AS{s.asn}",
            f"{s.passed}/{s.total}",
            str(s.blocked),
            f"[{color}]{s.verdict}[/{color}]",
        )
    console.print(table)
    console.print(f"Overall: [bold]{report.overall_verdict}[/bold]")
    return 0 if report.overall_verdict == "ok" else 1


async def _cmd_sni_brute(args: argparse.Namespace) -> int:
    console.print(f"[bold]SNI brute-force[/bold] against {args.target}:{args.port} (cap={args.max})")
    result = await find_working_sni(
        args.target,
        port=args.port,
        max_candidates=args.max,
        early_exit_after=args.early_exit,
    )
    _print_diagnostic(sni_to_diag(result))
    if result.working:
        console.print("[green]Working SNIs:[/green]")
        for s in result.working:
            console.print(f"  • {s}")
        return 0
    return 1


async def _cmd_telegram(args: argparse.Namespace) -> int:
    console.print("[bold]Telegram reachability probe[/bold] — DL + UL + DC ping (~30 MB download)")
    report = await check_telegram(
        proxy=args.via_proxy,
        stall_timeout=settings.telegram_stall_timeout,
        total_timeout=args.total_timeout,
    )
    _print_diagnostic(tg_to_diag(report))
    console.print(
        f"  Download: {report.download.status}, "
        f"{report.download.bytes_total / 1024 / 1024:.1f} MB in {report.download.duration_s:.1f}s"
    )
    console.print(
        f"  Upload:   {report.upload.status}, "
        f"{report.upload.bytes_total / 1024 / 1024:.1f} MB in {report.upload.duration_s:.1f}s"
    )
    console.print(f"  DCs reachable: {report.dc.reachable}/{report.dc.total}")
    return 0 if report.verdict == "ok" else 1


# ── Helpers ─────────────────────────────────────────────────────────────────


def _fmt_ans(ans: object) -> str:
    if isinstance(ans, list):
        return ",".join(ans[:2]) or "—"
    return str(ans) if ans else "—"


def _print_diagnostic(result) -> None:
    color = {"pass": "green", "warn": "yellow", "fail": "red", "timeout": "red"}.get(result.status.value, "white")
    console.print(f"[{color}]{result.status.value.upper()}[/{color}] {result.message}")


# Convenience for cli.main() → keeps imports focused
async def run(args: argparse.Namespace) -> int:
    return await dispatch(args)


# Allow `python -m xray_analyzer.cli_dpi dns foo.com` for local iteration only
if __name__ == "__main__":
    import sys

    parser = argparse.ArgumentParser(prog="dpi")
    subs = parser.add_subparsers(dest="command")
    register(subs)
    raw = parser.parse_args()
    sys.exit(asyncio.run(dispatch(raw)))
