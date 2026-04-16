"""Tests for diagnostics.error_classifier."""

from __future__ import annotations

import errno
import socket
import ssl

import aiohttp
import pytest

from xray_analyzer.core.models import CheckSeverity, CheckStatus
from xray_analyzer.diagnostics.error_classifier import (
    ErrorLabel,
    classify,
    collect_error_text,
    find_cause,
    get_errno_from_chain,
    label_to_status,
)


def _chain(outer: BaseException, inner: BaseException) -> BaseException:
    """Attach `inner` as __cause__ of `outer` without raising."""
    outer.__cause__ = inner
    return outer


class TestChainHelpers:
    def test_find_cause_direct_match(self):
        exc = ConnectionResetError("reset")
        assert find_cause(exc, ConnectionResetError) is exc

    def test_find_cause_nested(self):
        inner = ConnectionResetError("reset")
        outer = _chain(RuntimeError("wrap"), inner)
        assert find_cause(outer, ConnectionResetError) is inner

    def test_find_cause_missing(self):
        assert find_cause(RuntimeError("x"), ConnectionResetError) is None

    def test_get_errno_from_chain_prefers_first_set(self):
        inner = OSError(errno.ECONNREFUSED, "refused")
        outer = _chain(aiohttp.ClientConnectorError(connection_key=None, os_error=inner), inner)  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        assert get_errno_from_chain(outer) == errno.ECONNREFUSED

    def test_get_errno_none(self):
        assert get_errno_from_chain(RuntimeError("nope")) is None

    def test_collect_error_text_joins_chain(self):
        inner = OSError(errno.ECONNRESET, "Connection reset by peer")
        outer = _chain(RuntimeError("upstream fail"), inner)
        text = collect_error_text(outer)
        assert "upstream fail" in text
        assert "connection reset by peer" in text


class TestSSLClassification:
    def test_cert_expired(self):
        err = ssl.SSLCertVerificationError("certificate has expired")
        err.verify_code = 10
        label, detail = classify(err)
        assert label is ErrorLabel.TLS_MITM
        assert "expired" in detail

    def test_self_signed(self):
        err = ssl.SSLCertVerificationError("self-signed certificate")
        err.verify_code = 18
        label, _ = classify(err)
        assert label is ErrorLabel.TLS_MITM

    def test_unknown_ca(self):
        err = ssl.SSLCertVerificationError("unknown ca")
        err.verify_code = 20
        label, detail = classify(err)
        assert label is ErrorLabel.TLS_MITM
        assert "unknown ca" in detail.lower()

    def test_hostname_mismatch(self):
        err = ssl.SSLCertVerificationError("hostname mismatch")
        err.verify_code = 62
        label, _ = classify(err)
        assert label is ErrorLabel.TLS_MITM

    def test_bad_record_mac(self):
        err = ssl.SSLError("bad record mac")
        label, _ = classify(err)
        assert label is ErrorLabel.TLS_DPI

    def test_unexpected_eof(self):
        err = ssl.SSLError("EOF occurred in violation of protocol")
        label, _ = classify(err)
        assert label is ErrorLabel.TLS_DPI

    def test_unrecognized_name(self):
        err = ssl.SSLError("tlsv1 alert unrecognized_name")
        label, detail = classify(err)
        assert label is ErrorLabel.TLS_DPI
        assert "sni" in detail.lower()

    def test_protocol_version_block(self):
        err = ssl.SSLError("alert_protocol_version")
        label, _ = classify(err)
        assert label is ErrorLabel.TLS_BLOCK

    def test_wrong_version_number(self):
        err = ssl.SSLError("wrong version number")
        label, _ = classify(err)
        assert label is ErrorLabel.TLS_DPI

    def test_ssl_error_nested_inside_client_error(self):
        inner = ssl.SSLError("bad record mac")
        outer = _chain(RuntimeError("wrapped"), inner)
        label, _ = classify(outer)
        assert label is ErrorLabel.TLS_DPI


class TestDNSClassification:
    def test_gaierror_noname(self):
        err = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        label, detail = classify(err)
        assert label is ErrorLabel.DNS_FAIL
        assert "not found" in detail

    def test_gaierror_again(self):
        eai_again = getattr(socket, "EAI_AGAIN", -3)
        err = socket.gaierror(eai_again, "Temporary failure")
        label, _ = classify(err)
        assert label is ErrorLabel.DNS_FAIL

    def test_text_fallback_getaddrinfo(self):
        err = RuntimeError("getaddrinfo failed for host")
        label, _ = classify(err)
        assert label is ErrorLabel.DNS_FAIL


class TestTCPClassification:
    def test_refused_direct(self):
        err = ConnectionRefusedError("refused")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_REFUSED

    def test_refused_errno(self):
        err = OSError(errno.ECONNREFUSED, "refused")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_REFUSED

    def test_reset_direct(self):
        err = ConnectionResetError("reset")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_RST

    def test_reset_via_errno(self):
        err = OSError(errno.ECONNRESET, "Connection reset by peer")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_RST

    def test_aborted(self):
        err = ConnectionAbortedError("aborted")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_ABORT

    def test_broken_pipe(self):
        err = BrokenPipeError("broken pipe")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_ABORT

    def test_net_unreachable(self):
        err = OSError(errno.ENETUNREACH, "Network is unreachable")
        label, _ = classify(err)
        assert label is ErrorLabel.NET_UNREACH

    def test_host_unreachable(self):
        err = OSError(errno.EHOSTUNREACH, "No route to host")
        label, _ = classify(err)
        assert label is ErrorLabel.HOST_UNREACH


class TestTimeouts:
    def test_plain_timeout(self):
        err = TimeoutError("timed out")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_TIMEOUT

    def test_asyncio_timeout_chained(self):
        inner = TimeoutError()
        outer = _chain(RuntimeError("connect failed"), inner)
        label, _ = classify(outer)
        assert label is ErrorLabel.TCP_TIMEOUT

    def test_etimedout_errno(self):
        err = OSError(errno.ETIMEDOUT, "Connection timed out")
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_TIMEOUT


class TestAiohttpSpecific:
    def test_server_disconnected(self):
        err = aiohttp.ServerDisconnectedError()
        label, _ = classify(err)
        assert label is ErrorLabel.TCP_ABORT

    def test_client_payload_error(self):
        err = aiohttp.ClientPayloadError("payload is not completed")
        label, _ = classify(err)
        assert label is ErrorLabel.READ_ERR


class TestFallback:
    def test_generic(self):
        err = RuntimeError("something weird")
        label, detail = classify(err)
        assert label is ErrorLabel.GENERIC
        assert "something weird" in detail

    def test_generic_uses_type_name_when_str_empty(self):
        class CustomProbeError(Exception):
            pass

        label, detail = classify(CustomProbeError())
        assert label is ErrorLabel.GENERIC
        assert detail == "CustomProbeError"


class TestLabelToStatus:
    @pytest.mark.parametrize(
        ("label", "expected_status"),
        [
            (ErrorLabel.OK, CheckStatus.PASS),
            (ErrorLabel.TCP_TIMEOUT, CheckStatus.TIMEOUT),
            (ErrorLabel.TLS_MITM, CheckStatus.FAIL),
            (ErrorLabel.DNS_FAIL, CheckStatus.FAIL),
        ],
    )
    def test_mapping(self, label: ErrorLabel, expected_status: CheckStatus):
        status, severity = label_to_status(label)
        assert status is expected_status
        assert isinstance(severity, CheckSeverity)

    def test_every_label_has_mapping(self):
        for label in ErrorLabel:
            status, severity = label_to_status(label)
            assert isinstance(status, CheckStatus)
            assert isinstance(severity, CheckSeverity)
