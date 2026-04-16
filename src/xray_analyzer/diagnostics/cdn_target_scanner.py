"""Bulk CDN/hosting scan — answers "is Hetzner blocked by my ISP?".

Whereas `censor_checker` asks whether individual domains are blocked, this
scanner asks about the *infrastructure*: runs the fat-probe against a curated
list of ASN-bucketed IPs (Hetzner, Cloudflare, Akamai, AWS, OVH, Scaleway,
Contabo, Fastly, Google Cloud, Gcore, Oracle, …) and aggregates per-provider
verdicts.

Target list is shipped at `data/tcp16_targets.json` (copied from
https://github.com/Runnin4ik/dpi-detector under MIT). Upstream has a few
typos (`",port"` instead of `"port"`, duplicate IDs) which we sanitize at
load time rather than patching the file — makes pulling updates easier.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.data import DATA_DIR
from xray_analyzer.diagnostics.error_classifier import ErrorLabel
from xray_analyzer.diagnostics.fat_probe_checker import fat_probe

log = get_logger("cdn_target_scanner")


@dataclass(frozen=True)
class CdnTarget:
    """One entry from the curated target list."""

    id: str
    asn: str  # "24940" or "24940☆" — keep the star marker as-is for the table
    provider: str
    ip: str
    port: int
    sni: str | None = None


def _normalize_entry(raw: dict[str, Any]) -> CdnTarget | None:
    """Clean up upstream typos and produce a CdnTarget, or None if malformed."""
    ip = raw.get("ip")
    if not ip:
        return None

    # Upstream occasionally writes `,port` instead of `port`.
    port_val = raw.get("port")
    if port_val is None:
        port_val = raw.get(",port")
    if port_val is None:
        return None

    try:
        port = int(port_val)
    except (TypeError, ValueError):
        return None

    return CdnTarget(
        id=str(raw.get("id", f"TGT-{ip}")),
        asn=str(raw.get("asn", "-")),
        provider=str(raw.get("provider", "-")),
        ip=str(ip),
        port=port,
        sni=raw.get("sni"),
    )


def load_targets(path: os.PathLike[str] | str | None = None) -> list[CdnTarget]:
    """Load the bundled CDN target list. Pass `path` in tests to override.

    Duplicates (same IP+port) are dropped, keeping the first occurrence.
    Malformed rows are skipped with a debug log.
    """
    target_path = Path(path) if path else DATA_DIR / "tcp16_targets.json"
    with target_path.open(encoding="utf-8") as f:
        raw: list[dict[str, Any]] = json.load(f)

    seen: set[tuple[str, int]] = set()
    out: list[CdnTarget] = []
    for entry in raw:
        normalized = _normalize_entry(entry)
        if normalized is None:
            log.debug("Skipped malformed CDN target row", row=entry)
            continue
        key = (normalized.ip, normalized.port)
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


# ── Aggregation ─────────────────────────────────────────────────────────────

ProviderVerdict = str  # ok | partial | blocked
VERDICT_OK = "ok"
VERDICT_PARTIAL = "partial"
VERDICT_BLOCKED = "blocked"


@dataclass
class ProviderSummary:
    asn: str
    provider: str
    total: int
    passed: int
    blocked: int  # TCP_16_20 or abort inside fat-probe window
    errored: int  # DNS fail, timeout, refused, etc.
    verdict: ProviderVerdict

    @property
    def human(self) -> str:
        return (
            f"{self.provider} (AS{self.asn}): "
            f"{self.passed}/{self.total} OK"
            + (f", {self.blocked} blocked" if self.blocked else "")
            + (f", {self.errored} errored" if self.errored else "")
        )


@dataclass
class CdnScanReport:
    results: list[DiagnosticResult] = field(default_factory=list)
    summaries: list[ProviderSummary] = field(default_factory=list)
    overall_verdict: ProviderVerdict = VERDICT_OK


def _summarize_group(
    asn: str,
    provider: str,
    group_results: list[tuple[CdnTarget, ErrorLabel]],
) -> ProviderSummary:
    total = len(group_results)
    passed = sum(1 for _, label in group_results if label is ErrorLabel.OK)
    blocked = sum(
        1 for _, label in group_results if label in (ErrorLabel.TCP_16_20, ErrorLabel.TCP_ABORT, ErrorLabel.TCP_RST)
    )
    errored = total - passed - blocked

    if passed == total:
        verdict = VERDICT_OK
    elif passed == 0:
        verdict = VERDICT_BLOCKED
    else:
        verdict = VERDICT_PARTIAL

    return ProviderSummary(
        asn=asn,
        provider=provider,
        total=total,
        passed=passed,
        blocked=blocked,
        errored=errored,
        verdict=verdict,
    )


def _overall(summaries: list[ProviderSummary]) -> ProviderVerdict:
    if all(s.verdict == VERDICT_OK for s in summaries):
        return VERDICT_OK
    if all(s.verdict == VERDICT_BLOCKED for s in summaries):
        return VERDICT_BLOCKED
    return VERDICT_PARTIAL


async def scan_targets(
    targets: list[CdnTarget],
    *,
    max_parallel: int = 10,
    iterations: int = 16,
    chunk_size: int = 4000,
    connect_timeout: float = 8.0,
    read_timeout: float = 12.0,
    default_sni: str = "example.com",
) -> CdnScanReport:
    """Run fat-probe against every target concurrently, aggregate per-provider."""
    if not targets:
        return CdnScanReport()

    sem = asyncio.Semaphore(max_parallel)

    async def _one(target: CdnTarget) -> tuple[CdnTarget, ErrorLabel, DiagnosticResult]:
        sni = target.sni or (None if target.port == 80 else default_sni)
        async with sem:
            probe_res = await fat_probe(
                target.ip,
                port=target.port,
                sni=sni,
                iterations=iterations,
                chunk_size=chunk_size,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
            )

        status = CheckStatus.PASS if probe_res.label is ErrorLabel.OK else CheckStatus.FAIL
        severity = CheckSeverity.INFO if status == CheckStatus.PASS else CheckSeverity.ERROR
        diagnostic = DiagnosticResult(
            check_name="CDN Target Probe",
            status=status,
            severity=severity,
            message=(
                f"{target.provider} [{target.id}] {target.ip}:{target.port} "
                f"— {probe_res.label.value}: {probe_res.detail}"
            ),
            details={
                "id": target.id,
                "asn": target.asn,
                "provider": target.provider,
                "ip": target.ip,
                "port": target.port,
                "sni": sni,
                "label": probe_res.label.value,
                "drop_at_kb": probe_res.drop_at_kb,
                "rtt_ms": round(probe_res.rtt_ms, 2) if probe_res.rtt_ms else None,
            },
        )
        return target, probe_res.label, diagnostic

    gathered = await asyncio.gather(*[_one(t) for t in targets])

    grouped: dict[tuple[str, str], list[tuple[CdnTarget, ErrorLabel]]] = defaultdict(list)
    per_target_diagnostics: list[DiagnosticResult] = []
    for target, label, diagnostic in gathered:
        grouped[(target.asn, target.provider)].append((target, label))
        per_target_diagnostics.append(diagnostic)

    summaries = [_summarize_group(asn, provider, group) for (asn, provider), group in sorted(grouped.items())]

    return CdnScanReport(
        results=per_target_diagnostics,
        summaries=summaries,
        overall_verdict=_overall(summaries),
    )
