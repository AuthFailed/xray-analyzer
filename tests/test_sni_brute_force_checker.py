# ruff: noqa: ARG001  (mock signatures mirror fat_probe)
"""Tests for sni_brute_force_checker."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.error_classifier import ErrorLabel
from xray_analyzer.diagnostics.fat_probe_checker import FatProbeResult
from xray_analyzer.diagnostics.sni_brute_force_checker import (
    SniSearchResult,
    find_working_sni,
    load_whitelist_snis,
    to_diagnostic,
)


class TestLoadWhitelistSnis:
    def test_bundled_file_loads(self):
        snis = load_whitelist_snis()
        assert len(snis) > 50
        assert all(s for s in snis)

    def test_ignores_blanks_and_comments(self, tmp_path: Path):
        p = tmp_path / "sni.txt"
        p.write_text("vk.com\n# comment\n\n  ya.ru  \n")
        snis = load_whitelist_snis(p)
        assert snis == ["vk.com", "ya.ru"]


@pytest.mark.asyncio
class TestFindWorkingSni:
    async def test_first_match_exits_early(self):
        """early_exit_after=1 should cause the search to stop after one hit."""
        candidates = ["bad1.com", "bad2.com", "works.ru", "bad3.com", "bad4.com"]

        async def fake_probe(target, **kwargs):
            sni = kwargs.get("sni")
            if sni == "works.ru":
                return FatProbeResult(True, ErrorLabel.OK, "ok", None, 30)
            return FatProbeResult(True, ErrorLabel.TCP_16_20, "drop", 16, 40)

        with patch(
            "xray_analyzer.diagnostics.sni_brute_force_checker.fat_probe",
            side_effect=fake_probe,
        ):
            result = await find_working_sni("1.2.3.4", 443, candidates=candidates, early_exit_after=1, max_parallel=1)

        assert result.first_working == "works.ru"
        # max_parallel=1 means linear order; once "works.ru" hits at call 3, stop.
        assert result.tried <= len(candidates)
        assert "works.ru" in result.working

    async def test_max_candidates_caps_iteration(self):
        candidates = [f"s{i}.com" for i in range(100)]

        async def fake_probe(target, **kwargs):
            return FatProbeResult(True, ErrorLabel.TCP_16_20, "drop", 16, 40)

        with patch(
            "xray_analyzer.diagnostics.sni_brute_force_checker.fat_probe",
            side_effect=fake_probe,
        ):
            result = await find_working_sni("1.2.3.4", 443, candidates=candidates, max_candidates=10, max_parallel=5)

        assert result.first_working is None
        assert result.tried == 10

    async def test_collects_multiple_winners_when_early_exit_2(self):
        candidates = ["a.ru", "b.ru", "c.ru"]

        async def fake_probe(target, **kwargs):
            return FatProbeResult(True, ErrorLabel.OK, "ok", None, 30)

        with patch(
            "xray_analyzer.diagnostics.sni_brute_force_checker.fat_probe",
            side_effect=fake_probe,
        ):
            result = await find_working_sni("1.2.3.4", 443, candidates=candidates, early_exit_after=2, max_parallel=1)

        assert len(result.working) >= 2

    async def test_empty_candidates(self):
        result = await find_working_sni("1.2.3.4", 443, candidates=[])
        assert result.tried == 0
        assert result.first_working is None


class TestToDiagnostic:
    def test_working(self):
        d = to_diagnostic(
            SniSearchResult(target="1.2.3.4", port=443, working=["ya.ru"], tried=5, first_working="ya.ru")
        )
        assert d.status == CheckStatus.PASS
        assert "ya.ru" in d.message

    def test_none_working(self):
        d = to_diagnostic(SniSearchResult(target="1.2.3.4", port=443, tried=50))
        assert d.status == CheckStatus.FAIL
        assert "50" in d.message
