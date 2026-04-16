"""DNS tampering probe: cross-check direct UDP/53 vs DoH JSON.

Complements `dns_checker.check_dns_with_checkhost` (geo-distributed view via
Check-Host.net) with a self-contained, ISP-focused view: what does my
provider's UDP resolver answer, and does it agree with encrypted DNS?

For each domain, we ask one "healthy" UDP resolver (chosen from a 2-phase
liveness ping across the bundled list) AND one DoH resolver, then compare:
  - lists agree       → `ok`
  - UDP returns diff IPs but DoH is consistent   → `spoof`
  - UDP times out / errors, DoH works            → `intercept`
  - UDP returns NXDOMAIN/empty, DoH works        → `fake_nxdomain`/`fake_empty`
  - DoH blocked, UDP works                       → `doh_blocked`
  - neither answers                              → `all_dead`

Stub-IP harvesting: any IP that appears in UDP answers for **≥2 different
domains** is treated as an ISP splash/block page IP and returned alongside the
results, so downstream TLS/HTTP probes can tag resolved_ip ∈ stub_ips as
`ISP_PAGE`.

Adapted from https://github.com/Runnin4ik/dpi-detector (MIT), `core/dns_scanner.py`.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.data import DATA_DIR
from xray_analyzer.diagnostics.dns_checker import _is_fakedns_ip

log = get_logger("dns_dpi_prober")


# ── Data loading ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DnsServers:
    udp: list[tuple[str, str]]
    doh: list[tuple[str, str]]
    probe_domains: list[str]


def load_dns_servers(path: os.PathLike[str] | str | None = None) -> DnsServers:
    """Load the bundled DNS server list. Pass `path` in tests to override."""
    target = Path(path) if path else DATA_DIR / "dns_servers.json"
    with target.open(encoding="utf-8") as f:
        raw: dict[str, Any] = json.load(f)
    return DnsServers(
        udp=[tuple(entry) for entry in raw.get("udp", [])],  # type: ignore[misc]
        doh=[tuple(entry) for entry in raw.get("doh", [])],  # type: ignore[misc]
        probe_domains=list(raw.get("probe_domains", [])),
    )


# ── Raw UDP DNS wire format ─────────────────────────────────────────────────


def _build_dns_query(domain: str) -> bytes:
    tx_id = os.urandom(2)
    flags = b"\x01\x00"  # standard query, recursion desired
    qdcount = b"\x00\x01"
    ancount = nscount = arcount = b"\x00\x00"
    header = tx_id + flags + qdcount + ancount + nscount + arcount

    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode("ascii")
    qname += b"\x00"

    return header + qname + b"\x00\x01" + b"\x00\x01"  # QTYPE=A, QCLASS=IN


class _DnsParseError(Exception):
    pass


def _parse_dns_response(data: bytes, tx_id: bytes) -> list[str] | str:
    """Return list[ip] on success, or a literal string marker on known-bad.

    Markers: `"NXDOMAIN"`, `"EMPTY"`.
    Raises `_DnsParseError` on wire-format problems.
    """
    if len(data) < 12:
        raise _DnsParseError("response too short")
    if data[:2] != tx_id:
        raise _DnsParseError("transaction id mismatch")

    flags = struct.unpack(">H", data[2:4])[0]
    rcode = flags & 0x000F
    if rcode == 3:
        return "NXDOMAIN"
    if rcode != 0:
        raise _DnsParseError(f"RCODE {rcode}")

    qdcount, ancount, _, _ = struct.unpack(">HHHH", data[4:12])
    offset = 12

    def _skip_name(pos: int) -> int:
        while True:
            if pos >= len(data):
                break
            if (data[pos] & 0xC0) == 0xC0:
                return pos + 2
            length = data[pos]
            if length == 0:
                return pos + 1
            pos += length + 1
        return pos

    for _ in range(qdcount):
        offset = _skip_name(offset)
        offset += 4  # QTYPE + QCLASS

    ips: list[str] = []
    for _ in range(ancount):
        offset = _skip_name(offset)
        if offset + 10 > len(data):
            break
        atype, aclass, _, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if atype == 1 and aclass == 1 and rdlength == 4:
            ips.append(socket.inet_ntoa(rdata))

    return ips if ips else "EMPTY"


class _DnsDatagramProtocol(asyncio.DatagramProtocol):
    """Single-response datagram protocol used per query."""

    def __init__(self) -> None:
        self.future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:  # noqa: ARG002  (asyncio protocol contract)
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


async def _udp_resolve(nameserver: str, domain: str, timeout: float) -> list[str] | str:
    loop = asyncio.get_running_loop()
    req = _build_dns_query(domain)
    tx_id = req[:2]
    transport, protocol = await loop.create_datagram_endpoint(
        _DnsDatagramProtocol,
        remote_addr=(nameserver, 53),
    )
    try:
        transport.sendto(req)  # type: ignore[attr-defined]
        data = await asyncio.wait_for(protocol.future, timeout)  # type: ignore[attr-defined]
        return _parse_dns_response(data, tx_id)
    finally:
        transport.close()


# ── DoH probe (shared session) ──────────────────────────────────────────────


class _DohSessionHolder:
    session: aiohttp.ClientSession | None = None


def _get_doh_session() -> aiohttp.ClientSession:
    if _DohSessionHolder.session is None or _DohSessionHolder.session.closed:
        _DohSessionHolder.session = aiohttp.ClientSession(
            headers={"Accept": "application/dns-json"},
        )
    return _DohSessionHolder.session


async def close_doh_session() -> None:
    if _DohSessionHolder.session is not None and not _DohSessionHolder.session.closed:
        await _DohSessionHolder.session.close()
    _DohSessionHolder.session = None


async def _doh_resolve(
    url: str,
    domain: str,
    timeout: float,
    session: aiohttp.ClientSession | None = None,
) -> list[str] | str:
    own = session is None
    sess = session or _get_doh_session()
    try:
        async with sess.get(
            url,
            params={"name": domain, "type": "A"},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status != 200:
                return "BLOCKED"
            data = await resp.json(content_type=None)
    finally:
        if own:
            # When the caller didn't pass a shared session, we created a
            # throwaway one — but we don't actually construct one here; we use
            # the module-level holder. Nothing to close.
            pass

    if data.get("Status") == 3:
        return "NXDOMAIN"
    ips = [a.get("data", "") for a in data.get("Answer", []) if a.get("type") == 1]
    return ips if ips else "EMPTY"


# ── Verdict logic ───────────────────────────────────────────────────────────


DnsVerdict = str  # one of the literals below
VERDICT_OK = "ok"
VERDICT_SPOOF = "spoof"
VERDICT_INTERCEPT = "intercept"
VERDICT_FAKE_NXDOMAIN = "fake_nxdomain"
VERDICT_FAKE_EMPTY = "fake_empty"
VERDICT_DOH_BLOCKED = "doh_blocked"
VERDICT_ALL_DEAD = "all_dead"


def _classify_domain(
    udp_answer: list[str] | str | None,
    doh_answer: list[str] | str | None,
) -> DnsVerdict:
    udp_ips = udp_answer if isinstance(udp_answer, list) else None
    doh_ips = doh_answer if isinstance(doh_answer, list) else None

    if udp_ips and doh_ips:
        if set(udp_ips) == set(doh_ips):
            return VERDICT_OK
        # Many CDNs return anycast-variant IPs per resolver; only flag as spoof
        # when UDP answer contains at least one FakeDNS / known-bogon IP. The
        # downstream stub-IP consensus step can still elevate generic
        # "different but both legitimate-looking" to spoof via stub_ips.
        if any(_is_fakedns_ip(ip) for ip in udp_ips):
            return VERDICT_SPOOF
        return VERDICT_OK

    if doh_ips and not udp_ips:
        if udp_answer == "NXDOMAIN":
            return VERDICT_FAKE_NXDOMAIN
        if udp_answer == "EMPTY":
            return VERDICT_FAKE_EMPTY
        return VERDICT_INTERCEPT

    if udp_ips and not doh_ips:
        return VERDICT_DOH_BLOCKED

    return VERDICT_ALL_DEAD


# ── Liveness phase + batch resolve ──────────────────────────────────────────


async def _pick_alive_udp(
    servers: list[tuple[str, str]],
    probe_domain: str,
    timeout: float,
) -> tuple[str, str] | None:
    """Ping every UDP server with one probe domain; return the first that answers."""

    async def _ping(ip: str, name: str) -> tuple[str, str] | None:
        try:
            result = await _udp_resolve(ip, probe_domain, timeout)
            if isinstance(result, list):
                return (ip, name)
        except Exception as exc:
            log.debug("UDP DNS ping failed", ip=ip, name=name, error=str(exc))
        return None

    tasks = [asyncio.create_task(_ping(ip, name)) for ip, name in servers]
    alive: tuple[str, str] | None = None
    try:
        for done in asyncio.as_completed(tasks):
            result = await done
            if result is not None:
                alive = result
                break
    finally:
        for t in tasks:
            t.cancel()
    return alive


async def _pick_alive_doh(
    servers: list[tuple[str, str]],
    probe_domain: str,
    timeout: float,
    session: aiohttp.ClientSession,
) -> tuple[str, str] | None:
    async def _ping(url: str, name: str) -> tuple[str, str] | None:
        try:
            result = await _doh_resolve(url, probe_domain, timeout, session=session)
            if isinstance(result, list):
                return (url, name)
        except Exception as exc:
            log.debug("DoH ping failed", url=url, name=name, error=str(exc))
        return None

    tasks = [asyncio.create_task(_ping(url, name)) for url, name in servers]
    alive: tuple[str, str] | None = None
    try:
        for done in asyncio.as_completed(tasks):
            result = await done
            if result is not None:
                alive = result
                break
    finally:
        for t in tasks:
            t.cancel()
    return alive


async def _batch_udp(ip: str, domains: list[str], timeout: float) -> dict[str, list[str] | str | None]:
    async def _one(d: str) -> tuple[str, list[str] | str | None]:
        try:
            return d, await _udp_resolve(ip, d, timeout)
        except Exception:
            return d, None

    results = await asyncio.gather(*[_one(d) for d in domains])
    return dict(results)


async def _batch_doh(
    url: str,
    domains: list[str],
    timeout: float,
    session: aiohttp.ClientSession,
) -> dict[str, list[str] | str | None]:
    async def _one(d: str) -> tuple[str, list[str] | str | None]:
        try:
            return d, await _doh_resolve(url, d, timeout, session=session)
        except Exception:
            return d, None

    results = await asyncio.gather(*[_one(d) for d in domains])
    return dict(results)


def _harvest_stub_ips(
    answers: Mapping[str, list[str] | str | None],
    min_occurrences: int = 2,
) -> set[str]:
    """IPs returned by UDP for ≥N different domains → likely ISP splash/block page."""
    counter: Counter[str] = Counter()
    for ips in answers.values():
        if isinstance(ips, list):
            counter.update(set(ips))  # set() so duplicate IPs within one answer don't inflate
    return {ip for ip, count in counter.items() if count >= min_occurrences}


# ── Public API ──────────────────────────────────────────────────────────────


@dataclass
class DnsIntegrityReport:
    """Aggregate output of the DNS DPI prober."""

    results: list[DiagnosticResult] = field(default_factory=list)
    stub_ips: set[str] = field(default_factory=set)
    udp_server: tuple[str, str] | None = None
    doh_server: tuple[str, str] | None = None
    udp_available: bool = False
    doh_available: bool = False
    verdict_counts: Counter = field(default_factory=Counter)


def _short_message(verdict: DnsVerdict, udp_ans: Any, doh_ans: Any) -> str:
    def _fmt(ans: Any) -> str:
        if isinstance(ans, list):
            return ",".join(ans[:2]) or "-"
        return str(ans) if ans is not None else "unavail"

    return f"verdict={verdict} udp={_fmt(udp_ans)} doh={_fmt(doh_ans)}"


_VERDICT_STATUS: dict[str, tuple[CheckStatus, CheckSeverity]] = {
    VERDICT_OK: (CheckStatus.PASS, CheckSeverity.INFO),
    VERDICT_SPOOF: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    VERDICT_INTERCEPT: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    VERDICT_FAKE_NXDOMAIN: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    VERDICT_FAKE_EMPTY: (CheckStatus.FAIL, CheckSeverity.CRITICAL),
    VERDICT_DOH_BLOCKED: (CheckStatus.FAIL, CheckSeverity.ERROR),
    VERDICT_ALL_DEAD: (CheckStatus.FAIL, CheckSeverity.ERROR),
}


async def probe_dns_integrity(
    domains: list[str],
    timeout: float = 5.0,
    servers: DnsServers | None = None,
    session: aiohttp.ClientSession | None = None,
    udp_only: bool = False,
    doh_only: bool = False,
) -> DnsIntegrityReport:
    """Run UDP vs DoH comparison for each domain and produce a DnsIntegrityReport.

    Args:
        domains: list of FQDNs to probe.
        timeout: per-query timeout in seconds (applied to both UDP and DoH).
        servers: optional override for the bundled server list.
        session: pre-existing aiohttp session for DoH; one is created if None.
        udp_only / doh_only: run only one side of the comparison.
    """
    if not domains:
        return DnsIntegrityReport()

    servers = servers or load_dns_servers()
    probe_domain = servers.probe_domains[0] if servers.probe_domains else domains[0]
    report = DnsIntegrityReport()

    own_session = session is None
    sess = session or aiohttp.ClientSession(headers={"Accept": "application/dns-json"})
    try:
        udp_server: tuple[str, str] | None = None
        doh_server: tuple[str, str] | None = None
        udp_answers: dict[str, Any] = {}
        doh_answers: dict[str, Any] = {}

        if not doh_only:
            udp_server = await _pick_alive_udp(servers.udp, probe_domain, timeout)
            if udp_server:
                udp_answers = await _batch_udp(udp_server[0], domains, timeout)
            report.udp_server = udp_server
            report.udp_available = udp_server is not None

        if not udp_only:
            doh_server = await _pick_alive_doh(servers.doh, probe_domain, timeout, sess)
            if doh_server:
                doh_answers = await _batch_doh(doh_server[0], domains, timeout, sess)
            report.doh_server = doh_server
            report.doh_available = doh_server is not None

        report.stub_ips = _harvest_stub_ips(udp_answers) if udp_answers else set()

        for domain in domains:
            udp_ans = udp_answers.get(domain) if udp_server else None
            doh_ans = doh_answers.get(domain) if doh_server else None

            if udp_only:
                verdict = VERDICT_OK if isinstance(udp_ans, list) else VERDICT_ALL_DEAD
            elif doh_only:
                verdict = VERDICT_OK if isinstance(doh_ans, list) else VERDICT_ALL_DEAD
            else:
                verdict = _classify_domain(udp_ans, doh_ans)

            # Upgrade OK→spoof if the UDP answer intersects the harvested stub
            # set AND DoH does not corroborate. When DoH returns the same
            # answer as UDP, the "stub" is actually a legitimately shared CDN
            # IP, not a block page.
            if (
                verdict == VERDICT_OK
                and isinstance(udp_ans, list)
                and report.stub_ips
                and set(udp_ans) & report.stub_ips
                and (not isinstance(doh_ans, list) or set(udp_ans) != set(doh_ans))
            ):
                verdict = VERDICT_SPOOF

            status, severity = _VERDICT_STATUS[verdict]
            report.verdict_counts[verdict] += 1
            report.results.append(
                DiagnosticResult(
                    check_name="DNS Integrity",
                    status=status,
                    severity=severity,
                    message=f"{domain}: {_short_message(verdict, udp_ans, doh_ans)}",
                    details={
                        "domain": domain,
                        "verdict": verdict,
                        "udp_answer": udp_ans,
                        "doh_answer": doh_ans,
                        "udp_server": f"{udp_server[0]} ({udp_server[1]})" if udp_server else None,
                        "doh_server": f"{doh_server[0]} ({doh_server[1]})" if doh_server else None,
                    },
                )
            )
    finally:
        if own_session:
            await sess.close()

    return report
