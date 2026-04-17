# ruff: noqa: ARG001  (mock signatures deliberately mirror real resolver params)
"""Tests for diagnostics.dns_dpi_prober."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from unittest.mock import patch

import pytest

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.dns_dpi_prober import (
    VERDICT_ALL_DEAD,
    VERDICT_DOH_BLOCKED,
    VERDICT_FAKE_EMPTY,
    VERDICT_FAKE_NXDOMAIN,
    VERDICT_INTERCEPT,
    VERDICT_OK,
    VERDICT_SPOOF,
    DnsIntegrityReport,
    DnsServers,
    _build_dns_query,
    _classify_domain,
    _DnsParseError,
    _harvest_stub_ips,
    _parse_dns_response,
    load_dns_servers,
    probe_dns_integrity,
)

# ── Wire format ─────────────────────────────────────────────────────────────


class TestWireFormat:
    def test_build_query_header_shape(self):
        q = _build_dns_query("example.com")
        # 12-byte header + qname (1+7+1+3+1) + QTYPE (2) + QCLASS (2)
        assert len(q) == 12 + 13 + 4
        # flags = 0x0100 (standard query, RD)
        assert q[2:4] == b"\x01\x00"
        assert q[4:6] == b"\x00\x01"  # qdcount=1
        assert q[-4:] == b"\x00\x01\x00\x01"  # A / IN

    def test_build_query_encodes_labels(self):
        q = _build_dns_query("a.b.c")
        # label lengths must match
        assert q[12] == 1  # len("a")
        assert q[14] == 1  # len("b")
        assert q[16] == 1  # len("c")
        assert q[18] == 0  # root terminator

    def test_parse_nxdomain(self):
        tx_id = b"\xaa\xbb"
        # flags: response (0x8000) + RCODE 3 (NXDOMAIN) = 0x8003
        data = tx_id + struct.pack(">HHHHH", 0x8003, 0, 0, 0, 0)
        assert _parse_dns_response(data, tx_id) == "NXDOMAIN"

    def test_parse_empty_answer(self):
        tx_id = b"\xaa\xbb"
        # response, RCODE 0, 1 question, 0 answers
        data = tx_id + struct.pack(">HHHHH", 0x8000, 1, 0, 0, 0)
        # qname: "a\0" (length 1 + 'a' + root)
        data += b"\x01a\x00" + b"\x00\x01\x00\x01"
        assert _parse_dns_response(data, tx_id) == "EMPTY"

    def test_parse_two_a_records(self):
        tx_id = b"\x12\x34"
        header = tx_id + struct.pack(">HHHHH", 0x8000, 1, 2, 0, 0)
        qsec = b"\x01a\x00" + b"\x00\x01\x00\x01"
        # answer 1: compressed name ptr + type A + class IN + TTL + rdlen=4 + IP 1.2.3.4
        ans1 = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        ans2 = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x05\x06\x07\x08"
        result = _parse_dns_response(header + qsec + ans1 + ans2, tx_id)
        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_parse_rejects_wrong_tx_id(self):
        tx_id = b"\x00\x01"
        data = b"\xff\xff" + struct.pack(">HHHHH", 0x8000, 0, 0, 0, 0)
        with pytest.raises(_DnsParseError):
            _parse_dns_response(data, tx_id)

    def test_parse_rejects_short_payload(self):
        with pytest.raises(_DnsParseError):
            _parse_dns_response(b"too short", b"\x00\x01")


# ── Verdict classifier ──────────────────────────────────────────────────────


class TestClassifyDomain:
    def test_agreement_is_ok(self):
        assert _classify_domain(["1.1.1.1"], ["1.1.1.1"]) == VERDICT_OK

    def test_different_public_ips_not_flagged(self):
        # CDN anycast variance — both legitimate — must NOT be flagged as spoof
        # without other evidence (the stub-IP elevation handles the real case).
        assert _classify_domain(["104.16.0.1"], ["104.16.0.2"]) == VERDICT_OK

    def test_udp_fakedns_pool_treated_as_ok(self):
        # 198.18.0.x ∈ Xray FakeDNS pool — local FakeDNS intercepted UDP, not ISP spoofing
        assert _classify_domain(["198.18.0.5"], ["1.1.1.1"]) == VERDICT_OK

    def test_udp_nxdomain_while_doh_resolves(self):
        assert _classify_domain("NXDOMAIN", ["1.1.1.1"]) == VERDICT_FAKE_NXDOMAIN

    def test_udp_empty_while_doh_resolves(self):
        assert _classify_domain("EMPTY", ["1.1.1.1"]) == VERDICT_FAKE_EMPTY

    def test_udp_dead_while_doh_resolves(self):
        assert _classify_domain(None, ["1.1.1.1"]) == VERDICT_INTERCEPT

    def test_doh_blocked_but_udp_ok(self):
        assert _classify_domain(["1.1.1.1"], None) == VERDICT_DOH_BLOCKED

    def test_both_dead(self):
        assert _classify_domain(None, None) == VERDICT_ALL_DEAD


# ── Stub IP harvest ─────────────────────────────────────────────────────────


class TestHarvestStubIps:
    def test_ip_appearing_twice_harvested(self):
        answers = {
            "a.com": ["10.0.0.1"],
            "b.com": ["10.0.0.1"],
            "c.com": ["1.2.3.4"],
        }
        assert _harvest_stub_ips(answers) == {"10.0.0.1"}

    def test_single_occurrence_not_harvested(self):
        answers = {"a.com": ["10.0.0.1"], "b.com": ["1.2.3.4"]}
        assert _harvest_stub_ips(answers) == set()

    def test_ignores_non_lists(self):
        answers = {"a.com": "NXDOMAIN", "b.com": None, "c.com": ["1.2.3.4"]}
        assert _harvest_stub_ips(answers) == set()

    def test_set_semantics_per_domain(self):
        # Same IP returned twice for one domain is one occurrence, not two.
        answers = {"a.com": ["10.0.0.1", "10.0.0.1"], "b.com": ["9.9.9.9"]}
        assert _harvest_stub_ips(answers) == set()


# ── Data loading ────────────────────────────────────────────────────────────


class TestLoadDnsServers:
    def test_bundled_file_parses(self):
        servers = load_dns_servers()
        assert len(servers.udp) >= 5
        assert len(servers.doh) >= 3
        assert all(isinstance(x, tuple) and len(x) == 2 for x in servers.udp)

    def test_load_from_path(self, tmp_path: Path):
        payload = {
            "udp": [["8.8.8.8", "G"]],
            "doh": [["https://example/", "E"]],
            "probe_domains": ["x.com"],
        }
        p = tmp_path / "dns.json"
        p.write_text(json.dumps(payload))
        loaded = load_dns_servers(p)
        assert loaded.udp == [("8.8.8.8", "G")]
        assert loaded.doh == [("https://example/", "E")]
        assert loaded.probe_domains == ["x.com"]


# ── End-to-end orchestration (resolvers fully mocked) ───────────────────────


@pytest.mark.asyncio
class TestProbeOrchestration:
    async def test_empty_domains_returns_empty_report(self):
        report = await probe_dns_integrity([])
        assert report.results == []
        assert report.stub_ips == set()

    async def test_happy_path(self):
        servers = DnsServers(
            udp=[("8.8.8.8", "G")],
            doh=[("https://example/dns", "E")],
            probe_domains=["probe.com"],
        )

        async def fake_udp(ns, domain, timeout):
            return ["1.2.3.4"]

        async def fake_doh(url, domain, timeout, session=None):
            return ["1.2.3.4"]

        with (
            patch("xray_analyzer.diagnostics.dns_dpi_prober._udp_resolve", side_effect=fake_udp),
            patch("xray_analyzer.diagnostics.dns_dpi_prober._doh_resolve", side_effect=fake_doh),
        ):
            report = await probe_dns_integrity(["a.com", "b.com"], servers=servers)

        assert report.udp_available and report.doh_available
        assert len(report.results) == 2
        assert all(r.status == CheckStatus.PASS for r in report.results)
        assert report.verdict_counts[VERDICT_OK] == 2

    async def test_spoof_elevation_via_stub_ips(self):
        """If every domain returns the same UDP IP, it's a stub and OK→SPOOF."""
        servers = DnsServers(
            udp=[("8.8.8.8", "G")],
            doh=[("https://example/dns", "E")],
            probe_domains=["probe.com"],
        )

        async def fake_udp(ns, domain, timeout):
            return ["10.0.0.1"]

        async def fake_doh(url, domain, timeout, session=None):
            # DoH returns legit-but-different IP → no fakedns signal
            return ["104.16.0.1"]

        with (
            patch("xray_analyzer.diagnostics.dns_dpi_prober._udp_resolve", side_effect=fake_udp),
            patch("xray_analyzer.diagnostics.dns_dpi_prober._doh_resolve", side_effect=fake_doh),
        ):
            report = await probe_dns_integrity(["a.com", "b.com"], servers=servers)

        # 10.0.0.1 appears for both domains → harvested as stub → OK upgrades to SPOOF
        assert "10.0.0.1" in report.stub_ips
        assert report.verdict_counts[VERDICT_SPOOF] == 2
        assert all(r.details["verdict"] == VERDICT_SPOOF for r in report.results)

    async def test_doh_blocked(self):
        servers = DnsServers(
            udp=[("8.8.8.8", "G")],
            doh=[("https://doh.example/dns", "E")],
            probe_domains=["probe.com"],
        )

        async def fake_udp(ns, domain, timeout):
            return ["1.1.1.1"]

        async def fake_doh(url, domain, timeout, session=None):
            raise TimeoutError("DoH unreachable")

        with (
            patch("xray_analyzer.diagnostics.dns_dpi_prober._udp_resolve", side_effect=fake_udp),
            patch("xray_analyzer.diagnostics.dns_dpi_prober._doh_resolve", side_effect=fake_doh),
        ):
            report = await probe_dns_integrity(["a.com"], servers=servers)

        assert report.udp_available is True
        assert report.doh_available is False
        assert report.verdict_counts[VERDICT_DOH_BLOCKED] == 1

    async def test_udp_nxdomain_fake(self):
        servers = DnsServers(
            udp=[("8.8.8.8", "G")],
            doh=[("https://doh/", "E")],
            probe_domains=["probe.com"],
        )

        async def fake_udp(ns, domain, timeout):
            # Liveness probe ("probe.com") answers normally, target gets NXDOMAIN
            if domain == "probe.com":
                return ["9.9.9.9"]
            return "NXDOMAIN"

        async def fake_doh(url, domain, timeout, session=None):
            return ["1.2.3.4"]

        with (
            patch("xray_analyzer.diagnostics.dns_dpi_prober._udp_resolve", side_effect=fake_udp),
            patch("xray_analyzer.diagnostics.dns_dpi_prober._doh_resolve", side_effect=fake_doh),
        ):
            report = await probe_dns_integrity(["blocked.example"], servers=servers)

        assert report.verdict_counts[VERDICT_FAKE_NXDOMAIN] == 1

    async def test_shared_cdn_ip_is_not_spoof_when_doh_agrees(self):
        """Shared CDN hosting returns the same IP across many domains. If DoH
        corroborates UDP, we must not flag it as spoof — even though the IP
        clears the ≥2-domain stub threshold."""
        servers = DnsServers(
            udp=[("8.8.8.8", "G")],
            doh=[("https://doh/", "E")],
            probe_domains=["probe.com"],
        )

        async def fake_udp(ns, domain, timeout):
            return ["172.67.70.222"]  # e.g. Cloudflare shared CDN IP

        async def fake_doh(url, domain, timeout, session=None):
            return ["172.67.70.222"]  # DoH agrees — this is the real answer

        with (
            patch("xray_analyzer.diagnostics.dns_dpi_prober._udp_resolve", side_effect=fake_udp),
            patch("xray_analyzer.diagnostics.dns_dpi_prober._doh_resolve", side_effect=fake_doh),
        ):
            report = await probe_dns_integrity(["site1.example", "site2.example"], servers=servers)

        # Harvester still lists the IP (it IS shared across domains) ...
        assert "172.67.70.222" in report.stub_ips
        # ... but classification stays OK because DoH agreed
        assert report.verdict_counts[VERDICT_OK] == 2
        assert report.verdict_counts[VERDICT_SPOOF] == 0

    async def test_udp_only_skips_doh(self):
        servers = DnsServers(
            udp=[("8.8.8.8", "G")],
            doh=[("https://doh/", "E")],
            probe_domains=["probe.com"],
        )

        async def fake_udp(ns, domain, timeout):
            return ["1.1.1.1"]

        async def fake_doh(*args, **kwargs):
            raise AssertionError("DoH must not be called in udp_only mode")

        with (
            patch("xray_analyzer.diagnostics.dns_dpi_prober._udp_resolve", side_effect=fake_udp),
            patch("xray_analyzer.diagnostics.dns_dpi_prober._doh_resolve", side_effect=fake_doh),
        ):
            report = await probe_dns_integrity(["a.com"], servers=servers, udp_only=True)

        assert report.verdict_counts[VERDICT_OK] == 1
        assert report.doh_server is None


def test_report_dataclass_defaults():
    r = DnsIntegrityReport()
    assert r.results == []
    assert r.stub_ips == set()
    assert r.udp_server is None
