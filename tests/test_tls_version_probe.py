"""Tests for tls_version_probe + http_injection_probe (response evaluator + integration)."""

from __future__ import annotations

import ssl

import pytest
from aiohttp import ServerDisconnectedError
from aioresponses import aioresponses

from xray_analyzer.core.models import CheckStatus
from xray_analyzer.diagnostics.error_classifier import ErrorLabel
from xray_analyzer.diagnostics.http_injection_probe import probe_http_injection
from xray_analyzer.diagnostics.tls_version_probe import (
    _version_label,
    evaluate_response,
    probe_tls,
)


class TestEvaluateResponse:
    def test_200_is_ok(self):
        label, detail = evaluate_response(200, "", "example.com", None, None)
        assert label is ErrorLabel.OK
        assert "200" in detail

    def test_451_is_isp_page(self):
        label, detail = evaluate_response(451, "", "example.com", None, None)
        assert label is ErrorLabel.ISP_PAGE
        assert "451" in detail

    def test_same_domain_redirect_is_ok(self):
        label, _ = evaluate_response(302, "https://www.example.com/after", "example.com", None, None)
        assert label is ErrorLabel.OK

    def test_subdomain_redirect_is_ok(self):
        label, _ = evaluate_response(301, "https://api.example.com/", "example.com", None, None)
        assert label is ErrorLabel.OK

    def test_cross_domain_redirect_is_isp_page(self):
        label, detail = evaluate_response(302, "https://blockpage.isp.ru/", "example.com", None, None)
        assert label is ErrorLabel.ISP_PAGE
        assert "blockpage.isp.ru" in detail

    def test_resolved_ip_in_stub_set_flags_isp_page(self):
        label, detail = evaluate_response(200, "", "example.com", "10.0.0.1", {"10.0.0.1"})
        assert label is ErrorLabel.ISP_PAGE
        assert "stub" in detail.lower()

    def test_location_with_no_scheme_parsed_correctly(self):
        label, _ = evaluate_response(302, "example.com/other", "example.com", None, None)
        assert label is ErrorLabel.OK  # same host after adding https:// prefix

    def test_5xx_counts_as_reachable(self):
        # 5xx is usually upstream — not DPI — so we don't flag it
        label, _ = evaluate_response(502, "", "example.com", None, None)
        assert label is ErrorLabel.OK


class TestVersionLabel:
    def test_none_is_generic(self):
        assert _version_label(None) == "TLS"

    def test_tls12(self):
        assert _version_label(ssl.TLSVersion.TLSv1_2) == "TLS 1.2"

    def test_tls13(self):
        assert _version_label(ssl.TLSVersion.TLSv1_3) == "TLS 1.3"


@pytest.mark.asyncio
class TestProbeTls:
    async def test_http_451_flagged_as_isp_page(self):
        with aioresponses() as m:
            m.get("https://example.com:443/", status=451)
            result = await probe_tls("example.com")
        assert result.status == CheckStatus.FAIL
        assert result.details["label"] == ErrorLabel.ISP_PAGE.value
        assert result.check_name == "TLS"

    async def test_cross_domain_redirect(self):
        with aioresponses() as m:
            m.get(
                "https://example.com:443/",
                status=302,
                headers={"location": "https://blockpage.isp.ru/"},
            )
            result = await probe_tls("example.com")
        assert result.status == CheckStatus.FAIL
        assert result.details["label"] == ErrorLabel.ISP_PAGE.value

    async def test_happy_path(self):
        with aioresponses() as m:
            m.get("https://example.com:443/", status=200)
            result = await probe_tls("example.com")
        assert result.status == CheckStatus.PASS
        assert result.details["label"] == ErrorLabel.OK.value

    async def test_tls12_forced_label(self):
        with aioresponses() as m:
            m.get("https://example.com:443/", status=200)
            result = await probe_tls("example.com", forced_version=ssl.TLSVersion.TLSv1_2)
        assert result.check_name == "TLS 1.2"
        assert result.details["tls_version"] == "TLS 1.2"

    async def test_server_disconnect_becomes_abort(self):
        with aioresponses() as m:
            m.get("https://example.com:443/", exception=ServerDisconnectedError())
            result = await probe_tls("example.com")
        assert result.status == CheckStatus.FAIL
        assert result.details["label"] == ErrorLabel.TCP_ABORT.value


@pytest.mark.asyncio
class TestProbeHttpInjection:
    async def test_200_ok(self):
        with aioresponses() as m:
            m.get("http://example.com:80/", status=200)
            result = await probe_http_injection("example.com")
        assert result.status == CheckStatus.PASS
        assert result.check_name == "HTTP Injection"

    async def test_451_isp_page(self):
        with aioresponses() as m:
            m.get("http://example.com:80/", status=451)
            result = await probe_http_injection("example.com")
        assert result.status == CheckStatus.FAIL
        assert result.details["label"] == ErrorLabel.ISP_PAGE.value

    async def test_cross_domain_redirect(self):
        with aioresponses() as m:
            m.get(
                "http://example.com:80/",
                status=302,
                headers={"location": "http://warning.provider.net/"},
            )
            result = await probe_http_injection("example.com")
        assert result.details["label"] == ErrorLabel.ISP_PAGE.value

    async def test_stub_ip_hit(self):
        with aioresponses() as m:
            m.get("http://example.com:80/", status=200)
            result = await probe_http_injection("example.com", stub_ips={"10.0.0.1"}, resolved_ip="10.0.0.1")
        assert result.details["label"] == ErrorLabel.ISP_PAGE.value
