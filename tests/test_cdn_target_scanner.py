# ruff: noqa: ARG001  (mock signatures deliberately mirror fat_probe)
"""Tests for cdn_target_scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from xray_analyzer.diagnostics.cdn_target_scanner import (
    VERDICT_BLOCKED,
    VERDICT_OK,
    VERDICT_PARTIAL,
    CdnTarget,
    _normalize_entry,
    load_targets,
    scan_targets,
)
from xray_analyzer.diagnostics.error_classifier import ErrorLabel
from xray_analyzer.diagnostics.fat_probe_checker import FatProbeResult


class TestNormalizeEntry:
    def test_happy(self):
        t = _normalize_entry({"id": "X-1", "asn": "24940", "provider": "Hetzner", "ip": "1.2.3.4", "port": 443})
        assert t == CdnTarget("X-1", "24940", "Hetzner", "1.2.3.4", 443, None)

    def test_comma_port_typo_is_fixed(self):
        t = _normalize_entry(
            {
                "id": "X-2",
                "asn": "24940",
                "provider": "Hetzner HTTP",
                "ip": "5.6.7.8",
                ",port": 80,
            }
        )
        assert t is not None
        assert t.port == 80

    def test_missing_ip_returns_none(self):
        assert _normalize_entry({"id": "X", "port": 443}) is None

    def test_missing_port_returns_none(self):
        assert _normalize_entry({"id": "X", "ip": "1.2.3.4"}) is None

    def test_non_numeric_port_returns_none(self):
        assert _normalize_entry({"ip": "1.2.3.4", "port": "https"}) is None

    def test_sni_preserved(self):
        t = _normalize_entry({"ip": "1.2.3.4", "port": 443, "sni": "media.example.com"})
        assert t is not None
        assert t.sni == "media.example.com"

    def test_asn_with_star_preserved(self):
        t = _normalize_entry({"ip": "1.2.3.4", "port": 443, "asn": "24940☆"})
        assert t is not None
        assert t.asn == "24940☆"


class TestLoadTargets:
    def test_bundled_file_loads_and_dedups(self):
        targets = load_targets()
        assert len(targets) > 50  # upstream has ~100 entries, minus dupes
        # Upstream has a duplicate (HE-02 appears twice with different IPs, and
        # AK-10/AK-11 appears twice with/without sni). Dedup by (ip, port).
        seen = {(t.ip, t.port) for t in targets}
        assert len(seen) == len(targets)

    def test_from_override_path(self, tmp_path: Path):
        p = tmp_path / "t.json"
        p.write_text(
            json.dumps(
                [
                    {"id": "A-1", "asn": "100", "provider": "X", "ip": "1.1.1.1", "port": 443},
                    {"id": "B-1", "asn": "200", "provider": "Y", "ip": "2.2.2.2", "port": 443},
                ]
            )
        )
        targets = load_targets(p)
        assert len(targets) == 2

    def test_skips_malformed(self, tmp_path: Path):
        p = tmp_path / "t.json"
        p.write_text(json.dumps([{"id": "bad"}, {"ip": "1.1.1.1", "port": 443}]))
        targets = load_targets(p)
        assert len(targets) == 1
        assert targets[0].ip == "1.1.1.1"


# ── scan orchestration ─────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestScanTargets:
    async def test_empty_list(self):
        report = await scan_targets([])
        assert report.results == []
        assert report.summaries == []
        assert report.overall_verdict == VERDICT_OK

    async def test_all_ok(self):
        targets = [
            CdnTarget("A", "100", "Prov", "1.1.1.1", 443),
            CdnTarget("B", "100", "Prov", "1.1.1.2", 443),
        ]

        async def fake_probe(*args, **kwargs):
            return FatProbeResult(alive=True, label=ErrorLabel.OK, detail="ok", drop_at_kb=None, rtt_ms=30)

        with patch(
            "xray_analyzer.diagnostics.cdn_target_scanner.fat_probe",
            side_effect=fake_probe,
        ):
            report = await scan_targets(targets)

        assert len(report.summaries) == 1
        s = report.summaries[0]
        assert s.passed == 2
        assert s.verdict == VERDICT_OK
        assert report.overall_verdict == VERDICT_OK

    async def test_all_blocked_single_provider(self):
        targets = [
            CdnTarget("A", "100", "Prov", "1.1.1.1", 443),
            CdnTarget("B", "100", "Prov", "1.1.1.2", 443),
        ]

        async def fake_probe(*args, **kwargs):
            return FatProbeResult(
                alive=True,
                label=ErrorLabel.TCP_16_20,
                detail="drop at 16 KB",
                drop_at_kb=16,
                rtt_ms=40,
            )

        with patch(
            "xray_analyzer.diagnostics.cdn_target_scanner.fat_probe",
            side_effect=fake_probe,
        ):
            report = await scan_targets(targets)

        assert report.summaries[0].verdict == VERDICT_BLOCKED
        assert report.summaries[0].blocked == 2
        assert report.overall_verdict == VERDICT_BLOCKED

    async def test_partial(self):
        targets = [
            CdnTarget("A", "100", "Prov", "1.1.1.1", 443),
            CdnTarget("B", "100", "Prov", "1.1.1.2", 443),
        ]

        call_count = {"n": 0}

        async def fake_probe(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return FatProbeResult(True, ErrorLabel.OK, "ok", None, 30)
            return FatProbeResult(True, ErrorLabel.TCP_16_20, "drop", 16, 40)

        with patch(
            "xray_analyzer.diagnostics.cdn_target_scanner.fat_probe",
            side_effect=fake_probe,
        ):
            report = await scan_targets(targets)

        assert report.summaries[0].verdict == VERDICT_PARTIAL
        assert report.summaries[0].passed == 1
        assert report.summaries[0].blocked == 1

    async def test_providers_grouped_independently(self):
        targets = [
            CdnTarget("A", "100", "ProvA", "1.1.1.1", 443),
            CdnTarget("B", "200", "ProvB", "2.2.2.2", 443),
        ]

        async def fake_probe(target, **kwargs):
            # First provider OK, second BLOCKED
            if target == "1.1.1.1":
                return FatProbeResult(True, ErrorLabel.OK, "ok", None, 30)
            return FatProbeResult(True, ErrorLabel.TCP_16_20, "drop", 16, 40)

        with patch(
            "xray_analyzer.diagnostics.cdn_target_scanner.fat_probe",
            side_effect=fake_probe,
        ):
            report = await scan_targets(targets)

        assert len(report.summaries) == 2
        verdicts = {s.provider: s.verdict for s in report.summaries}
        assert verdicts == {"ProvA": VERDICT_OK, "ProvB": VERDICT_BLOCKED}
        assert report.overall_verdict == VERDICT_PARTIAL
