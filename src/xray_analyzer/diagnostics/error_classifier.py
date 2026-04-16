"""Exception taxonomy for network / TLS / DNS probes.

Walks `__cause__` / `__context__` chains to classify any probe failure into a
single `ErrorLabel` + short human-readable detail. Every new DPI-related check
routes its exception branches through `classify()` so the rest of the codebase
can rely on a stable vocabulary instead of ad-hoc strings.

Adapted from https://github.com/Runnin4ik/dpi-detector (MIT) — Linux-only,
aiohttp-aware. Windows Winsock constants intentionally omitted.
"""

from __future__ import annotations

import errno
import re
import socket
import ssl
from enum import StrEnum

import aiohttp

from xray_analyzer.core.models import CheckSeverity, CheckStatus


class ErrorLabel(StrEnum):
    """Stable taxonomy for probe failure modes."""

    OK = "ok"

    # DNS
    DNS_FAIL = "dns_fail"  # resolution failure (NXDOMAIN, servfail, timeout)
    DNS_FAKE = "dns_fake"  # suspicious answer (stub IP, bogon, 198.18/15)

    # TCP / L4
    TCP_TIMEOUT = "tcp_timeout"
    TCP_REFUSED = "tcp_refused"
    TCP_RST = "tcp_rst"
    TCP_ABORT = "tcp_abort"
    NET_UNREACH = "net_unreach"
    HOST_UNREACH = "host_unreach"
    POOL_TIMEOUT = "pool_timeout"

    # TLS
    TLS_DPI = "tls_dpi"  # handshake/record-layer manipulation by a middle-box
    TLS_MITM = "tls_mitm"  # bad certificate (self-signed, unknown CA, expired, hostname mismatch)
    TLS_BLOCK = "tls_block"  # explicit protocol-version / cipher block

    # L7 / DPI observable
    TCP_16_20 = "tcp_16_20"  # connection dropped in the 16-20 KB "fat-probe" window
    ISP_PAGE = "isp_page"  # redirect to an ISP splash / HTTP 451
    READ_ERR = "read_err"  # generic read-side failure

    # Fallback
    GENERIC = "generic"


_MAX_CHAIN_DEPTH = 10


def _walk_chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(seen) < _MAX_CHAIN_DEPTH:
        seen.append(current)
        current = current.__cause__ or current.__context__
    return seen


def find_cause[E: BaseException](exc: BaseException, target_type: type[E]) -> E | None:
    """First exception in the chain that `isinstance` matches `target_type`."""
    for link in _walk_chain(exc):
        if isinstance(link, target_type):
            return link
    return None


def get_errno_from_chain(exc: BaseException) -> int | None:
    """First non-None `errno` found walking the `__cause__`/`__context__` chain."""
    for link in _walk_chain(exc):
        if isinstance(link, OSError) and link.errno is not None:
            return link.errno
    return None


def collect_error_text(exc: BaseException) -> str:
    return " | ".join(str(link).lower() for link in _walk_chain(exc))


_TRAILING_PAREN_RE = re.compile(r"\s*\(_*\s*$")
_WHITESPACE_RE = re.compile(r"\s+")


def _clean_detail(detail: str) -> str:
    if not detail:
        return ""
    detail = detail.replace("The operation did not complete", "TLS aborted")
    detail = _TRAILING_PAREN_RE.sub("", detail)
    detail = _WHITESPACE_RE.sub(" ", detail).strip()
    return detail[:80]


def _classify_ssl(err: ssl.SSLError) -> tuple[ErrorLabel, str]:
    msg = str(err).lower()

    if isinstance(err, ssl.SSLCertVerificationError):
        code = getattr(err, "verify_code", None)
        if code == 10 or "expired" in msg:
            return ErrorLabel.TLS_MITM, "certificate expired"
        if code in (18, 19) or "self-signed" in msg or "self signed" in msg:
            return ErrorLabel.TLS_MITM, "self-signed certificate"
        if code == 20 or "unknown ca" in msg:
            return ErrorLabel.TLS_MITM, "unknown CA"
        if code == 62 or "hostname mismatch" in msg:
            return ErrorLabel.TLS_MITM, "hostname mismatch"
        return ErrorLabel.TLS_MITM, "certificate verification failed"

    dpi_interruption = (
        "eof",
        "unexpected eof",
        "eof occurred in violation",
        "operation did not complete",
        "bad record mac",
        "decryption failed",
        "decrypt",
    )
    if any(token in msg for token in dpi_interruption):
        return ErrorLabel.TLS_DPI, "handshake aborted / bad record mac"

    if "unrecognized name" in msg or "unrecognized_name" in msg:
        return ErrorLabel.TLS_DPI, "SNI alert"
    if "alert handshake" in msg or "sslv3_alert_handshake" in msg:
        return ErrorLabel.TLS_DPI, "handshake alert"
    if "record_layer_failure" in msg or "record layer failure" in msg:
        return ErrorLabel.TLS_DPI, "record layer failure"
    if any(
        token in msg
        for token in (
            "illegal parameter",
            "decode error",
            "decoding error",
            "record overflow",
            "oversized",
            "bad key share",
            "bad_key_share",
        )
    ):
        return ErrorLabel.TLS_DPI, "handshake manipulated"

    if "wrong version number" in msg:
        return ErrorLabel.TLS_DPI, "non-TLS reply"
    if "protocol version" in msg or "alert_protocol_version" in msg:
        return ErrorLabel.TLS_BLOCK, "TLS version blocked"
    if "no shared cipher" in msg or "cipher" in msg:
        return ErrorLabel.TLS_MITM, "cipher mismatch"

    if isinstance(err, ssl.SSLZeroReturnError):
        return ErrorLabel.TLS_DPI, "unexpected close_notify"

    if "handshake" in msg:
        return ErrorLabel.TLS_DPI, "handshake failure"

    return ErrorLabel.TLS_DPI, _clean_detail(str(err)) or "SSL error"


def _classify_gai(err: socket.gaierror) -> tuple[ErrorLabel, str]:
    code = getattr(err, "errno", None)
    if code in (socket.EAI_NONAME,):
        return ErrorLabel.DNS_FAIL, "domain not found"
    eai_again = getattr(socket, "EAI_AGAIN", -3)
    if code == eai_again:
        return ErrorLabel.DNS_FAIL, "DNS timeout / temporary failure"
    return ErrorLabel.DNS_FAIL, "DNS error"


def classify(exc: BaseException) -> tuple[ErrorLabel, str]:
    """Walk the exception chain and pick the most informative label + detail.

    Precedence (most specific first):
      1. SSL errors anywhere in the chain → TLS_DPI / TLS_MITM / TLS_BLOCK
      2. DNS resolution errors → DNS_FAIL
      3. aiohttp pool timeout → POOL_TIMEOUT
      4. TCP-level cases by errno or cause type → RST / ABORT / REFUSED / TIMEOUT
      5. Network/host unreachability by errno
      6. aiohttp payload / server-disconnect → READ_ERR (typically DPI mid-stream)
      7. Plain timeouts → TCP_TIMEOUT
      8. Fallback → GENERIC
    """
    # 1. SSL — check before anything else; a wrapped SSL error hiding inside
    #    aiohttp.ClientConnectorError is still the root cause.
    ssl_err = find_cause(exc, ssl.SSLError)
    if ssl_err is not None:
        return _classify_ssl(ssl_err)

    # Some aiohttp builds expose SSL failures without chaining — sniff the text.
    text = collect_error_text(exc)
    if "sslv3_alert" in text or ("alert" in text and "handshake" in text):
        if "handshake_failure" in text or "handshake failure" in text:
            return ErrorLabel.TLS_DPI, "handshake alert"
        if "unrecognized_name" in text:
            return ErrorLabel.TLS_DPI, "SNI alert"
        if "protocol_version" in text:
            return ErrorLabel.TLS_BLOCK, "TLS version alert"
        return ErrorLabel.TLS_DPI, "TLS alert"

    # 2. DNS
    gai = find_cause(exc, socket.gaierror)
    if gai is not None:
        return _classify_gai(gai)
    if any(
        token in text
        for token in (
            "getaddrinfo failed",
            "name resolution",
            "name or service not known",
            "nodename nor servname",
        )
    ):
        return ErrorLabel.DNS_FAIL, "DNS error"

    # 3. Pool exhaustion
    if "pool timeout" in text or "connection pool is full" in text:
        return ErrorLabel.POOL_TIMEOUT, "connector pool exhausted"

    # 4. TCP-level causes
    en = get_errno_from_chain(exc)

    if find_cause(exc, ConnectionRefusedError) is not None or en == errno.ECONNREFUSED or "refused" in text:
        return ErrorLabel.TCP_REFUSED, "TCP connection refused"

    if find_cause(exc, ConnectionResetError) is not None or en == errno.ECONNRESET or "connection reset" in text:
        return ErrorLabel.TCP_RST, "TCP connection reset"

    aborted_errno = getattr(errno, "ECONNABORTED", 103)
    if (
        find_cause(exc, ConnectionAbortedError) is not None
        or en == aborted_errno
        or "connection aborted" in text
        or "broken pipe" in text
    ):
        return ErrorLabel.TCP_ABORT, "TCP connection aborted"

    if en == errno.ENETUNREACH or "network is unreachable" in text:
        return ErrorLabel.NET_UNREACH, "network unreachable"

    if en == errno.EHOSTUNREACH or "no route to host" in text:
        return ErrorLabel.HOST_UNREACH, "no route to host"

    # 5. aiohttp-specific signals that usually mean DPI mid-stream
    if isinstance(exc, aiohttp.ServerDisconnectedError) or "server disconnected" in text:
        return ErrorLabel.TCP_ABORT, "server disconnected early"
    if isinstance(exc, aiohttp.ClientPayloadError) or "payload is not completed" in text:
        return ErrorLabel.READ_ERR, "payload truncated"

    # 6. Timeouts
    if (
        isinstance(exc, TimeoutError)
        or find_cause(exc, TimeoutError) is not None
        or en == errno.ETIMEDOUT
        or "timed out" in text
        or "connect timeout" in text
    ):
        return ErrorLabel.TCP_TIMEOUT, "TCP/connect timeout"

    if "all connection attempts failed" in text:
        return ErrorLabel.TCP_REFUSED, "all connection attempts failed"

    return ErrorLabel.GENERIC, _clean_detail(str(exc)) or type(exc).__name__


# Suggested CheckStatus/CheckSeverity mapping for callers that want to emit
# DiagnosticResult without duplicating severity logic. Callers are free to
# override for their local context.
_LABEL_SEVERITY: dict[ErrorLabel, tuple[CheckStatus, CheckSeverity]] = {
    ErrorLabel.OK: (CheckStatus.PASS, CheckSeverity.INFO),
    ErrorLabel.DNS_FAIL: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    ErrorLabel.DNS_FAKE: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.TCP_TIMEOUT: (CheckStatus.TIMEOUT, CheckSeverity.ERROR),
    ErrorLabel.TCP_REFUSED: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.TCP_RST: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.TCP_ABORT: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.NET_UNREACH: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    ErrorLabel.HOST_UNREACH: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    ErrorLabel.POOL_TIMEOUT: (CheckStatus.FAIL, CheckSeverity.WARNING),
    ErrorLabel.TLS_DPI: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.TLS_MITM: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    ErrorLabel.TLS_BLOCK: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.TCP_16_20: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.ISP_PAGE: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    ErrorLabel.READ_ERR: (CheckStatus.FAIL, CheckSeverity.ERROR),
    ErrorLabel.GENERIC: (CheckStatus.FAIL, CheckSeverity.ERROR),
}


def label_to_status(label: ErrorLabel) -> tuple[CheckStatus, CheckSeverity]:
    """Suggested (status, severity) pair for a given ErrorLabel."""
    return _LABEL_SEVERITY[label]
