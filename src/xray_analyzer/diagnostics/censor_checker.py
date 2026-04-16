"""Censor-check: Test web resources through proxy for blocking/censorship detection.

This module replicates the behavior of the bash script by Nikola Tesla
(https://t.me/tracerlab) exactly, with all checks implemented the same way.
"""

import asyncio
import contextlib
import ipaddress
import os
import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import aiohttp
from aiohttp import ClientTimeout

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult, HostDiagnostic

log = get_logger("censor_checker")

# URL for Russia mobile internet whitelist
WHITELIST_URL = (
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"
)

# URLs for itdoginfo/allow-domains lists (raw plain-domain format)
ALLOW_DOMAINS_BASE = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main"
ALLOW_DOMAINS_LISTS: dict[str, tuple[str, str]] = {
    "russia-inside": (
        f"{ALLOW_DOMAINS_BASE}/Russia/inside-raw.lst",
        "Russia inside (domains blocked in Russia — foreign sites restricted by RKN)",
    ),
    "russia-outside": (
        f"{ALLOW_DOMAINS_BASE}/Russia/outside-raw.lst",
        "Russia outside (Russian domains for users abroad)",
    ),
    "ukraine-inside": (
        f"{ALLOW_DOMAINS_BASE}/Ukraine/inside-raw.lst",
        "Ukraine inside (domains blocked in Ukraine)",
    ),
}

# Default list of domains to check (from bash script)
DEFAULT_CENSOR_DOMAINS: list[str] = [
    "youtube.com",
    "instagram.com",
    "facebook.com",
    "x.com",
    "patreon.com",
    "linkedin.com",
    "signal.org",
    "tiktok.com",
    "api.telegram.org",
    "web.whatsapp.com",
    "discord.com",
    "viber.com",
    "chatgpt.com",
    "grok.com",
    "reddit.com",
    "twitch.tv",
    "netflix.com",
    "rutracker.org",
    "nnmclub.to",
    "digitalocean.com",
    "api.cloudflare.com",
    "speedtest.net",
    "aws.amazon.com",
    "ooni.org",
    "amnezia.org",
    "torproject.org",
    "proton.me",
    "github.com",
    "google.com",
]

# AI/Social domains with regional blocking detection (from bash script)
AI_REGIONAL_DOMAINS: set[str] = {
    "chatgpt.com",
    "grok.com",
    "netflix.com",
}

# Known RKN spoof IPs (from bash script)
# Rostelecom, MTS, Beeline, Megafon
RKN_STUB_IPS: set[str] = {
    "195.208.4.1",
    "195.208.5.1",
    "188.186.157.35",
    "80.93.183.168",
    "213.87.154.141",
    "92.101.255.255",
}

# DPI blocking keywords (from bash script)
DPI_BLOCKING_KEYWORDS: list[re.Pattern] = [
    re.compile(r"blocked", re.IGNORECASE),
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"access.denied", re.IGNORECASE),
    re.compile(r"roscomnadzor", re.IGNORECASE),
    re.compile(r"rkn", re.IGNORECASE),
    re.compile(r"firewall", re.IGNORECASE),
    re.compile(r"censorship", re.IGNORECASE),
    re.compile(r"prohibited", re.IGNORECASE),
    re.compile(r"restricted", re.IGNORECASE),
]

# AI regional blocking keywords (from bash script)
AI_BLOCKING_KEYWORDS: list[re.Pattern] = [
    re.compile(r"sorry, you have been blocked", re.IGNORECASE),
    re.compile(r"you are unable to access", re.IGNORECASE),
    re.compile(r"not available in your region", re.IGNORECASE),
    re.compile(r"restricted in your country", re.IGNORECASE),
    re.compile(r"access denied due to location", re.IGNORECASE),
    re.compile(r"blocked in your area", re.IGNORECASE),
    re.compile(r"unable to load site", re.IGNORECASE),
    re.compile(r"if you are using a vpn", re.IGNORECASE),
    re.compile(r"Not Available", re.IGNORECASE),
]

# Cloudflare challenge keywords (from bash script)
CLOUDFLARE_CHALLENGE_KEYWORDS: list[re.Pattern] = [
    re.compile(r"just a moment", re.IGNORECASE),
    re.compile(r"enable javascript and cookies", re.IGNORECASE),
]

# User agents (from bash script)
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
)

SNI_DUMMY_IP = "192.0.2.1"  # Dummy IP for SNI test (from bash script)

# Harmless SNI used for variance probing. Wikipedia is almost never censored
# worldwide and its IPs are well-connected, so a failure with this SNI is highly
# unlikely to be DPI-related and more likely a real network fault.
SNI_HARMLESS = "en.wikipedia.org"

# Public DoH resolvers used for cross-checking local DNS answers.
DOH_RESOLVERS: list[str] = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# Fast-RST threshold: DPI middleboxes inject RST / block pages in well under 100 ms.
# Real server timeouts or intercontinental round-trips take much longer.
DPI_FAST_RST_MS = 150

# Suspicious IP ranges. A DoH-vs-local DNS disagreement is only considered
# tampering when the local answer falls here — plain CDN/anycast disagreement
# (Cloudflare, Akamai, AWS) is normal and must not be flagged.
# - 198.18.0.0/15: RFC 2544 benchmarking range, commonly abused by RU ISPs as a
#   "bypass" destination for SNI-proxying transparent middleboxes.
# - 0.0.0.0/8, 127.0.0.0/8, 240.0.0.0/4: bogons/loopback/reserved.
# - Plus the explicit RKN stub IPs already defined above.
_SUSPICIOUS_NETS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("240.0.0.0/4"),
]


def _is_suspicious_ip(ip: str) -> bool:
    """True if the IP is in a bogon/stub range or an explicit RKN stub."""
    if ip in RKN_STUB_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    return any(addr in net for net in _SUSPICIOUS_NETS)


class DomainStatus(StrEnum):
    """Status of domain check."""

    OK = "OK"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"


@dataclass
class DpiSignals:
    """
    Structured DPI/censorship signals gathered for one domain.

    Each field is either a raw observation (None/empty = not measured) or a
    derived boolean flag. Aggregated in DomainCheckResult.details["dpi_signals"].
    """

    keyword_hit: bool = False
    sni_dummy_hit: bool = False
    sni_dummy_fail_ms: float = 0.0  # time until RST/timeout on the 192.0.2.1 probe
    sni_dummy_fast_rst: bool = False  # sni_dummy_fail_ms < DPI_FAST_RST_MS → likely injected
    sni_variance_suspect: bool = False
    sni_variance: dict[str, str] = field(default_factory=dict)  # per-SNI outcome
    fingerprint_variance_suspect: bool = False
    fingerprint_variance: dict[str, str] = field(default_factory=dict)  # per-profile outcome
    host_header_injection: bool = False
    host_header_code: int = 0
    http3_reachable: bool | None = None  # None = not probed
    doh_mismatch: bool = False
    doh_ips: list[str] = field(default_factory=list)

    def any_hit(self) -> bool:
        # DoH/DNS mismatch is *not* a DPI signal — kept as a separate DNS-layer
        # diagnostic. Only actual DPI-layer probes count toward the DPI verdict.
        return (
            self.keyword_hit
            or self.sni_dummy_hit
            or self.sni_variance_suspect
            or self.fingerprint_variance_suspect
            or self.host_header_injection
        )


@dataclass
class DomainCheckResult:
    """Result of checking a single domain."""

    domain: str
    status: DomainStatus
    block_type: str = ""  # Can be composite: "HTTP(S)/DPI", "TLS/SSL/DPI", etc.
    http_code: int = 0
    https_code: int = 0
    tls_valid: bool = False
    ips: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class CensorCheckSummary:
    """Summary of censor-check results."""

    total: int
    ok: int
    blocked: int
    partial: int
    results: list[DomainCheckResult] = field(default_factory=list)
    duration_seconds: float = 0.0
    proxy_url: str = ""


def _is_rkn_spoof(ip: str) -> bool:
    """Check if IP is a known RKN spoof address (from bash script)."""
    return ip in RKN_STUB_IPS


async def _resolve_dns(domain: str, _timeout: int = 5) -> list[str]:
    """
    Resolve domain DNS and return list of IPs.
    Equivalent to: nslookup "$domain" | awk '/^Address: / && !/#/ {print $2}'
    """
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(domain, 443)
        # Filter out localhost
        ips = list({info[4][0] for info in infos if info[4][0] not in ("::1", "127.0.0.1")})
        return ips
    except Exception as e:
        log.debug("DNS resolution failed", domain=domain, error=str(e))
        return []


async def _fetch_http_code(
    url: str,
    proxy_url: str = "",
    timeout: int = 4,
    retries: int = 2,
    user_agent: str = USER_AGENT,
    extra_headers: dict[str, str] | None = None,
    resolve_to_ip: str | None = None,
) -> int:
    """
    Fetch URL and return HTTP status code.
    Equivalent to: curl -s -o /dev/null --retry 2 --connect-timeout 4 --max-time 4 -4 -A "$USER_AGENT" -w "%{http_code}"

    If resolve_to_ip is set, resolves domain to that IP (like curl --resolve).
    """
    timeout_cfg = ClientTimeout(connect=timeout, total=timeout)

    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }
    if extra_headers:
        headers.update(extra_headers)

    # For SNI test with dummy IP, we need to manipulate the connection
    if resolve_to_ip:
        # We can't use aiohttp's built-in resolution for this
        # We'll use subprocess curl instead for this specific case
        return await _fetch_with_curl(url, proxy_url, timeout, retries, user_agent, extra_headers, resolve_to_ip)

    for attempt in range(retries):
        async with aiohttp.ClientSession(max_line_size=65536, max_field_size=65536) as session:
            try:
                kwargs: dict[str, Any] = {
                    "timeout": timeout_cfg,
                    "headers": headers,
                    "allow_redirects": True,
                    "ssl": True,
                }

                if proxy_url:
                    kwargs["proxy"] = proxy_url

                async with session.get(url, **kwargs) as response:
                    return response.status
            except Exception as e:
                log.debug("HTTP fetch failed", url=url, attempt=attempt + 1, retries=retries, error=str(e))
                if attempt < retries - 1:
                    await asyncio.sleep(0.5)
                    continue

    return 0


async def _fetch_with_curl(
    url: str,
    proxy_url: str = "",
    timeout: int = 4,
    retries: int = 2,
    user_agent: str = USER_AGENT,
    extra_headers: dict[str, str] | None = None,
    resolve_to_ip: str | None = None,
) -> int:
    """
    Use curl subprocess for fetching (needed for --resolve and some edge cases).
    Equivalent to bash curl commands.
    """
    curl_cmd = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "--retry",
        str(retries),
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
        "-4",  # IPv4 only
        "-A",
        user_agent,
        "-w",
        "%{http_code}",
    ]

    if proxy_url:
        if proxy_url.startswith("http://") or proxy_url.startswith("https://"):
            curl_cmd.extend(["--proxy", proxy_url])
        else:
            curl_cmd.extend(["--proxy", proxy_url])

    if resolve_to_ip:
        # Extract domain from URL
        domain = url.split("://", maxsplit=1)[1].split("/", maxsplit=1)[0]
        curl_cmd.extend(["--resolve", f"{domain}:443:{resolve_to_ip}"])

    curl_cmd.append(url)

    # Add extra headers
    if extra_headers:
        for key, value in extra_headers.items():
            curl_cmd.extend(["-H", f"{key}: {value}"])

    for attempt in range(retries):
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *curl_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            http_code = stdout.decode().strip()

            if http_code and http_code.isdigit():
                return int(http_code)
        except Exception as e:
            log.debug("curl failed", url=url, attempt=attempt + 1, retries=retries, error=str(e))
            if attempt < retries - 1:
                await asyncio.sleep(0.5)
                continue
        finally:
            # Reap the process if communicate() was interrupted (e.g. CancelledError).
            if proc is not None and proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()

    return 0


async def _check_certificate(domain: str, timeout: int = 4, verbose: bool = False) -> bool:
    """
    Verify TLS certificate via a native async handshake: chain validation + expiry.

    Equivalent in intent to `openssl s_client -verify 5` + notAfter check from the
    bash script, but without spawning openssl/date subprocesses.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout,
        )
        ssl_obj: ssl.SSLObject | None = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return False

        cert = ssl_obj.getpeercert()
        not_after = cert.get("notAfter") if cert else None
        if not not_after:
            return True  # chain verified; absence of notAfter is unusual but not a blocker

        # OpenSSL format: "Jun  1 12:00:00 2026 GMT"
        expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        if expire_dt < datetime.now(UTC):
            if verbose:
                log.info("Certificate expired", domain=domain, not_after=not_after)
            return False
        return True
    except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
        if verbose:
            log.info("TLS verification failed", domain=domain, error=str(e))
        return False
    except (TimeoutError, OSError) as e:
        log.debug("TLS connection failed", domain=domain, error=str(e))
        return False
    except Exception as e:
        log.debug("Certificate check failed", domain=domain, error=str(e))
        return False
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def _check_tcp_port(ip: str, port: int, timeout: int = 4) -> bool:
    """
    Check TCP connectivity to IP:port.
    Equivalent to: nc -z -w "$TIMEOUT" "$ip" "$port"
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True
    except Exception:
        return False


async def _dpi_keyword_probe(domain: str, timeout: int = 4) -> bool:
    """Send a request with a suspicious UA and grep response for block-page keywords."""
    try:
        headers = {"User-Agent": "Suspicious-Agent TLS/1.3"}
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                f"https://{domain}",
                timeout=ClientTimeout(connect=timeout, total=timeout),
                headers=headers,
                ssl=True,
            ) as response,
        ):
            text = await response.text()
            return any(pattern.search(text) for pattern in DPI_BLOCKING_KEYWORDS)
    except Exception:
        return False


async def _dpi_sni_probe(domain: str, timeout: int = 4) -> tuple[bool, float, int]:
    """
    Native SNI-to-dummy-IP probe (replaces `curl --resolve domain:443:192.0.2.1`).

    Opens a TLS connection to 192.0.2.1 (TEST-NET-1, unroutable) while sending the
    target domain in SNI. A genuine connection cannot complete — but a DPI middlebox
    that rewrites traffic based on SNI will synthesize a 4xx/5xx block page in response.

    Returns (hit, elapsed_ms_until_outcome, http_code). elapsed_ms < DPI_FAST_RST_MS
    when a hit also means the response was injected (not a real server reply) since
    nothing downstream of us should be able to answer for 192.0.2.1 that quickly.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    writer: asyncio.StreamWriter | None = None
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(SNI_DUMMY_IP, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout,
        )
        writer.write(
            b"GET / HTTP/1.1\r\n"
            b"Host: " + domain.encode("ascii", "ignore") + b"\r\n"
            b"User-Agent: " + USER_AGENT.encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        elapsed_ms = (time.monotonic() - t0) * 1000
        match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", data)
        if match:
            code = int(match.group(1))
            return (400 <= code < 600), elapsed_ms, code
        return False, elapsed_ms, 0
    except TimeoutError, ssl.SSLError, OSError, socket.gaierror:
        return False, (time.monotonic() - t0) * 1000, 0
    except Exception as e:
        log.debug("SNI probe failed", domain=domain, error=str(e))
        return False, (time.monotonic() - t0) * 1000, 0
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def _sni_variance_probe(domain: str, target_ip: str, timeout: int = 4) -> tuple[bool, dict[str, str]]:
    """
    To the *real* target IP, run three TLS handshakes: no-SNI, wrong-SNI, target-SNI.

    DPI that blocks based on SNI matches your target domain will RST only the
    target-SNI handshake while letting the others through. When the outcomes
    diverge (target fails, others succeed), SNI-based DPI is confirmed — a
    stronger signal than the 192.0.2.1 probe, which also fires on captive portals.
    """
    outcomes: dict[str, str] = {}

    async def _one(sni: str | None, label: str) -> str:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        writer: asyncio.StreamWriter | None = None
        try:
            # server_hostname=None disables SNI entirely; empty string is invalid.
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, 443, ssl=ctx, server_hostname=sni),
                timeout=timeout,
            )
            return "ok"
        except TimeoutError, ssl.SSLError, OSError:
            return "fail"
        except Exception as e:
            log.debug("SNI variance leg failed", domain=domain, label=label, error=str(e))
            return "fail"
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    results = await asyncio.gather(
        _one(None, "no_sni"),
        _one(SNI_HARMLESS, "harmless_sni"),
        _one(domain, "target_sni"),
    )
    outcomes["no_sni"], outcomes["harmless_sni"], outcomes["target_sni"] = results

    # Suspect SNI-based DPI when target fails while at least one of the benign
    # handshakes succeeds on the same IP.
    suspect = outcomes["target_sni"] == "fail" and (outcomes["no_sni"] == "ok" or outcomes["harmless_sni"] == "ok")
    return suspect, outcomes


async def _tls_fingerprint_probe(domain: str, target_ip: str, timeout: int = 4) -> tuple[bool, dict[str, str]]:
    """
    Two handshakes with differently shaped SSLContexts. Pure stdlib, so this is a
    weaker approximation of `curl-impersonate` — it catches the coarsest
    fingerprint-based DPI (e.g., blocking anything that isn't a browser-shaped
    ClientHello with modern ALPN) but won't fool sophisticated middleboxes.
    """

    async def _handshake(ctx: ssl.SSLContext, label: str) -> str:
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, 443, ssl=ctx, server_hostname=domain),
                timeout=timeout,
            )
            return "ok"
        except TimeoutError, ssl.SSLError, OSError:
            return "fail"
        except Exception as e:
            log.debug("Fingerprint leg failed", domain=domain, label=label, error=str(e))
            return "fail"
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    default_ctx = ssl.create_default_context()
    default_ctx.check_hostname = False
    default_ctx.verify_mode = ssl.CERT_NONE

    browser_ctx = ssl.create_default_context()
    browser_ctx.check_hostname = False
    browser_ctx.verify_mode = ssl.CERT_NONE
    # Chrome-ish: TLS 1.2+, ALPN h2/http1.1, modern cipher ordering.
    browser_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    browser_ctx.set_alpn_protocols(["h2", "http/1.1"])
    with contextlib.suppress(ssl.SSLError):
        browser_ctx.set_ciphers(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
        )

    default_result, browser_result = await asyncio.gather(
        _handshake(default_ctx, "python_default"),
        _handshake(browser_ctx, "chrome_like"),
    )
    outcomes = {"python_default": default_result, "chrome_like": browser_result}
    suspect = default_result != browser_result
    return suspect, outcomes


async def _plain_http_host_probe(domain: str, timeout: int = 4) -> tuple[bool, int]:
    """
    Raw HTTP to 192.0.2.1:80 with `Host: <target>`. Like the SNI probe but for
    plaintext HTTP — catches Host-header-based DPI that TLS probes miss.
    """
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(SNI_DUMMY_IP, 80),
            timeout=timeout,
        )
        writer.write(
            b"GET / HTTP/1.1\r\n"
            b"Host: " + domain.encode("ascii", "ignore") + b"\r\n"
            b"User-Agent: " + USER_AGENT.encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", data)
        if match:
            code = int(match.group(1))
            return (400 <= code < 600), code
        return False, 0
    except TimeoutError, OSError:
        return False, 0
    except Exception as e:
        log.debug("Host-header probe failed", domain=domain, error=str(e))
        return False, 0
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


class _QuicProbeProtocol(asyncio.DatagramProtocol):
    """Receives any UDP reply; we don't parse QUIC, presence is the signal."""

    def __init__(self, fut: asyncio.Future[bytes]) -> None:
        self._fut = fut

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        del addr
        if not self._fut.done():
            self._fut.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._fut.done():
            self._fut.set_exception(exc)


async def _http3_probe(target_ip: str, timeout: int = 4) -> bool | None:
    """
    QUIC reachability probe. Sends a 1-RTT Initial with an *unsupported* version
    (0xbabababa). Per RFC 9000 §17.2.1 the server MUST reply with a Version
    Negotiation packet. Any UDP response at all = UDP/443 + QUIC speaker present
    = HTTP/3 reachable. Timeout = filtered (or server doesn't run H3).

    Returns None on socket error so the caller can distinguish "didn't measure"
    from "definitely blocked".
    """
    # 15-byte packet: long header (0xc0) + unknown version + DCID(8 bytes random) + SCID(0).
    packet = b"\xc0" + b"\xba\xba\xba\xba" + b"\x08" + os.urandom(8) + b"\x00"

    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()
    transport: asyncio.DatagramTransport | None = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _QuicProbeProtocol(fut),
            remote_addr=(target_ip, 443),
        )
        transport.sendto(packet)
        try:
            await asyncio.wait_for(fut, timeout=timeout)
            return True
        except TimeoutError:
            return False
    except OSError:
        return None
    finally:
        if transport is not None:
            transport.close()


async def _doh_resolve(domain: str, timeout: int = 4) -> list[str]:
    """Resolve via Cloudflare DoH and return the A records."""
    ips: list[str] = []
    url = "https://cloudflare-dns.com/dns-query"
    headers = {"Accept": "application/dns-json"}
    params = {"name": domain, "type": "A"}
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                url,
                params=params,
                headers=headers,
                timeout=ClientTimeout(total=timeout),
            ) as response,
        ):
            if response.status != 200:
                return ips
            payload = await response.json(content_type=None)
            for ans in payload.get("Answer", []) or []:
                if ans.get("type") == 1 and isinstance(ans.get("data"), str):
                    ips.append(ans["data"])
    except Exception as e:
        log.debug("DoH resolve failed", domain=domain, error=str(e))
    return ips


async def _collect_dpi_signals(
    domain: str,
    local_ips: list[str],
    timeout: int = 4,
) -> DpiSignals:
    """
    Run every DPI/censorship signal concurrently and aggregate.

    Uses the first resolved IP as the target for SNI-variance, fingerprint and
    HTTP/3 probes (all need a real endpoint). Probes that don't need an IP
    (keyword, SNI-dummy, host-header, DoH) run in parallel regardless.
    """
    target_ip = local_ips[0] if local_ips else ""

    # Assemble tasks; every coroutine always runs — we branch on target_ip below
    # by short-circuiting specific probes to trivial awaitables.
    async def _skip_variance() -> tuple[bool, dict[str, str]]:
        return False, {}

    async def _skip_fingerprint() -> tuple[bool, dict[str, str]]:
        return False, {}

    async def _skip_h3() -> bool | None:
        return None

    results = await asyncio.gather(
        _dpi_keyword_probe(domain, timeout=timeout),
        _dpi_sni_probe(domain, timeout=timeout),
        (_sni_variance_probe(domain, target_ip, timeout=timeout) if target_ip else _skip_variance()),
        (_tls_fingerprint_probe(domain, target_ip, timeout=timeout) if target_ip else _skip_fingerprint()),
        _plain_http_host_probe(domain, timeout=timeout),
        (_http3_probe(target_ip, timeout=timeout) if target_ip else _skip_h3()),
        _doh_resolve(domain, timeout=timeout),
        return_exceptions=False,
    )
    (
        keyword_hit,
        (sni_hit, sni_fail_ms, _sni_code),
        (sni_var_suspect, sni_var_outcomes),
        (fp_suspect, fp_outcomes),
        (host_hit, host_code),
        h3_reachable,
        doh_ips,
    ) = results

    # DoH mismatch: we only flag as *tampering* when the local answer is in a
    # known-suspicious range (RKN stubs, 198.18/15, bogons). A plain set
    # difference would fire on every Cloudflare/Akamai/AWS site — most DNS
    # "mismatches" are just anycast/CDN variance between resolvers.
    doh_mismatch = (
        bool(doh_ips)
        and bool(local_ips)
        and not (set(doh_ips) & set(local_ips))
        and any(_is_suspicious_ip(ip) for ip in local_ips)
    )

    return DpiSignals(
        keyword_hit=keyword_hit,
        sni_dummy_hit=sni_hit,
        sni_dummy_fail_ms=round(sni_fail_ms, 1),
        sni_dummy_fast_rst=sni_hit and sni_fail_ms < DPI_FAST_RST_MS,
        sni_variance_suspect=sni_var_suspect,
        sni_variance=sni_var_outcomes,
        fingerprint_variance_suspect=fp_suspect,
        fingerprint_variance=fp_outcomes,
        host_header_injection=host_hit,
        host_header_code=host_code,
        http3_reachable=h3_reachable,
        doh_mismatch=doh_mismatch,
        doh_ips=doh_ips,
    )


def _dpi_label(sig: DpiSignals) -> str:
    """Pick the most informative single label for a set of DPI signals."""
    if sig.sni_variance_suspect:
        return "DPI/SNI"
    if sig.fingerprint_variance_suspect:
        return "DPI/FINGERPRINT"
    if sig.host_header_injection:
        return "DPI/HOST"
    if sig.sni_dummy_fast_rst:
        return "DPI/RST"
    if sig.sni_dummy_hit:
        return "DPI/SNI-DUMMY"
    if sig.keyword_hit:
        return "DPI/KEYWORD"
    return "DPI"


async def _check_dpi_blocking(domain: str, timeout: int = 4) -> bool:
    """
    Thin bool wrapper kept for callers that only need a yes/no verdict.

    Prefer `_collect_dpi_signals()` directly when you want structured output.
    """
    keyword_hit, sni_tuple = await asyncio.gather(
        _dpi_keyword_probe(domain, timeout=timeout),
        _dpi_sni_probe(domain, timeout=timeout),
    )
    return keyword_hit or sni_tuple[0]


async def _check_ai_regional_blocking(domain: str, timeout: int = 4, proxy_url: str = "") -> bool:
    """
    Check if AI/social domain shows a regional-block page (ChatGPT/Grok/Netflix style).

    Sends a Chrome-shaped request; matches known "not available in your region"
    phrases. A Cloudflare "just a moment" challenge is explicitly treated as NOT
    blocked. aiohttp handles gzip/deflate/br transparently (replaces `curl --compressed`).
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Connection": "keep-alive",
    }
    try:
        async with aiohttp.ClientSession(max_line_size=65536, max_field_size=65536) as session:
            kwargs: dict[str, Any] = {
                "timeout": ClientTimeout(connect=timeout, total=timeout),
                "headers": headers,
                "allow_redirects": True,
                "ssl": True,
            }
            if proxy_url:
                kwargs["proxy"] = proxy_url
            async with session.get(f"https://{domain}", **kwargs) as response:
                text = await response.text(errors="ignore")
    except Exception:
        return False

    if any(pattern.search(text) for pattern in CLOUDFLARE_CHALLENGE_KEYWORDS):
        return False
    return any(pattern.search(text) for pattern in AI_BLOCKING_KEYWORDS)


async def check_domain(
    domain: str,
    proxy_url: str = "",
    timeout: int = 4,
) -> DomainCheckResult:
    """
    Check a single domain for censorship/blocking (exactly like bash script).
    """
    result = DomainCheckResult(
        domain=domain,
        status=DomainStatus.OK,
        block_type="",
    )

    # 1. DNS resolution (like bash: nslookup "$domain")
    ips = await _resolve_dns(domain)
    result.ips = ips

    if not ips:
        result.status = DomainStatus.BLOCKED
        result.block_type = "DNS"
        return result

    # 2. Check for RKN spoof IPs
    for ip in ips:
        if _is_rkn_spoof(ip):
            result.status = DomainStatus.BLOCKED
            result.block_type = "DNS-SPOOF"
            result.details["rkn_stub_ip"] = ip
            return result

    # 3. TCP connectivity check (port 443 first, then port 80)
    ip_ok = False

    for ip in ips:
        if await _check_tcp_port(ip, 443, timeout=timeout):
            ip_ok = True
            break

    if not ip_ok:
        for ip in ips:
            if await _check_tcp_port(ip, 80, timeout=timeout):
                ip_ok = True
                break

    if not ip_ok:
        result.status = DomainStatus.BLOCKED
        result.block_type = "IP/TCP"
        return result

    # 4-6. TLS + HTTP/HTTPS + full DPI signal suite in parallel — all network-bound.
    tls_valid, http_code, https_code, dpi_signals = await asyncio.gather(
        _check_certificate(domain, timeout=timeout),
        _fetch_http_code(f"http://{domain}", proxy_url=proxy_url, timeout=timeout, retries=2),
        _fetch_http_code(f"https://{domain}", proxy_url=proxy_url, timeout=timeout, retries=2),
        _collect_dpi_signals(domain, ips, timeout=timeout),
    )
    # TCP ok but both HTTP codes zero — more likely a timeout under load
    # (e.g. local Xray FakeDNS) than a real block. Retry serially with doubled
    # timeout; healthy domains never enter this branch.
    if ip_ok and http_code == 0 and https_code == 0:
        retry_timeout = timeout * 2
        https_code = await _fetch_http_code(f"https://{domain}", proxy_url=proxy_url, timeout=retry_timeout, retries=1)
        if https_code == 0:
            http_code = await _fetch_http_code(
                f"http://{domain}", proxy_url=proxy_url, timeout=retry_timeout, retries=1
            )

    result.tls_valid = tls_valid
    if not tls_valid:
        result.block_type = "TLS/SSL"

    result.http_code = http_code
    result.https_code = https_code

    # Suppress doh_mismatch if the site is actually reachable: a synthetic IP
    # (e.g. 198.18/15 from Xray FakeDNS) that still routes successfully is local
    # split-tunneling, not tampering.
    http_accessible = (200 <= http_code < 400) or (200 <= https_code < 400)
    if dpi_signals.doh_mismatch and http_accessible:
        dpi_signals.doh_mismatch = False

    result.details["dpi_signals"] = dpi_signals

    # Handle HTTP redirects (like bash: if [[ "$http_code" =~ 3[0-9][0-9] ]])
    if 300 <= http_code < 400:
        log.debug(f"HTTP redirect detected for {domain}, falling back to HTTPS")
        http_code = https_code

    # Determine block_type based on HTTP codes
    if http_code == 0 and https_code == 0:
        if ip_ok:
            result.block_type = "HTTP(S)"
        else:
            result.block_type = "IP/HTTP"
        result.status = DomainStatus.BLOCKED
    elif (400 <= http_code < 600) and (400 <= https_code < 600):
        result.block_type = "HTTP-RESPONSE"
        result.status = DomainStatus.PARTIAL

    # DPI verdict: annotate block_type only when a probe provides evidence strong
    # enough to change the story. "Strong" = SNI-variance confirmed (target-SNI
    # fails, benign SNI succeeds), host-header injection, fast-RST on the
    # 192.0.2.1 probe, or DoH mismatch. The bare keyword probe stays a soft signal.
    if dpi_signals.any_hit():
        result.details["dpi_detected"] = True
        strong = (
            dpi_signals.sni_variance_suspect
            or dpi_signals.host_header_injection
            or dpi_signals.sni_dummy_fast_rst
            or dpi_signals.fingerprint_variance_suspect
        )
        blocked_or_partial = result.status != DomainStatus.OK or (http_code == 0 and https_code == 0)
        if strong or blocked_or_partial:
            label = _dpi_label(dpi_signals)
            if result.block_type:
                result.block_type = f"{result.block_type}/{label}"
            else:
                result.block_type = label

    # 7. AI/Social regional blocking check (like bash: if [[ " ${AI_DOMAINS[*]} " =~ " ${domain} " ]])
    if domain in AI_REGIONAL_DOMAINS and await _check_ai_regional_blocking(
        domain, timeout=timeout, proxy_url=proxy_url
    ):
        result.block_type = "REGIONAL"
        result.http_code = 0
        result.https_code = 0
        result.status = DomainStatus.BLOCKED

    # Final status determination (like bash script)
    if result.status == DomainStatus.OK:
        if http_code == 0 and https_code == 0:
            result.status = DomainStatus.BLOCKED
        elif 200 <= http_code < 400 or 200 <= https_code < 400:
            result.status = DomainStatus.OK
        else:
            result.status = DomainStatus.PARTIAL

    # block_type describes *why* a domain is blocked/partial.
    # If the domain is accessible, clear any leftover block_type (e.g. TLS/SSL on an
    # HTTP-only site, or DPI signals that didn't prevent access).
    if result.status == DomainStatus.OK:
        result.block_type = ""

    return result


async def _tcp_ping(host: str, port: int, count: int = 3, timeout: int = 4) -> DiagnosticResult:
    """TCP ping: measure connection latency to host:port."""
    start = time.monotonic()
    latencies: list[float] = []
    failures = 0

    for _ in range(count):
        t0 = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            latencies.append((time.monotonic() - t0) * 1000)
        except Exception:
            failures += 1

    duration_ms = (time.monotonic() - start) * 1000
    loss_pct = round(failures / count * 100, 1)

    details: dict[str, Any] = {
        "host": host,
        "port": port,
        "attempts": count,
        "packet_loss_pct": loss_pct,
    }
    if latencies:
        details["latency_min_ms"] = round(min(latencies), 1)
        details["latency_max_ms"] = round(max(latencies), 1)
        details["latency_avg_ms"] = round(sum(latencies) / len(latencies), 1)

    if not latencies:
        return DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"All {count} attempts to {host}:{port} failed",
            details=details,
            duration_ms=duration_ms,
        )
    if failures:
        return DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.WARN,
            severity=CheckSeverity.WARNING,
            message=(f"{host}:{port} — avg {details['latency_avg_ms']}ms, loss {loss_pct}%"),
            details=details,
            duration_ms=duration_ms,
        )
    return DiagnosticResult(
        check_name="TCP Ping",
        status=CheckStatus.PASS,
        severity=CheckSeverity.INFO,
        message=f"{host}:{port} — avg {details['latency_avg_ms']}ms, min {details['latency_min_ms']}ms",
        details=details,
        duration_ms=duration_ms,
    )


async def check_domain_verbose(
    domain: str,
    port: int = 443,
    proxy_url: str = "",
    timeout: int = 4,
    on_step_complete: Callable[[DiagnosticResult], None] | None = None,
    on_step_start: Callable[[str], None] | None = None,
) -> HostDiagnostic:
    """
    Run all checks on a single domain and return step-by-step DiagnosticResults.

    Steps: DNS → RKN spoof → TCP → TCP ping → TLS → HTTP/HTTPS → DPI → AI regional.
    Each step that fails is reported; later steps that depend on a failed step are skipped.
    """
    diag = HostDiagnostic(host=domain)
    http_accessible = False  # tracks whether HTTP/HTTPS returned a successful response

    def _emit(result: DiagnosticResult) -> DiagnosticResult:
        diag.add_result(result)
        if on_step_complete:
            on_step_complete(result)
        return result

    # --- 1. DNS ---
    if on_step_start:
        on_step_start("DNS")
    t0 = time.monotonic()
    ips = await _resolve_dns(domain, _timeout=timeout)
    dns_ms = (time.monotonic() - t0) * 1000

    spoof_ip: str | None = None
    for ip in ips:
        if _is_rkn_spoof(ip):
            spoof_ip = ip
            break

    if not ips:
        _emit(
            DiagnosticResult(
                check_name="DNS",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                message=f"DNS resolution failed for {domain} — domain may be DNS-blocked",
                details={"domain": domain},
                recommendations=["DNS is being blocked — try a different DNS resolver (8.8.8.8, 1.1.1.1)"],
                duration_ms=dns_ms,
            )
        )
        return diag

    if spoof_ip:
        _emit(
            DiagnosticResult(
                check_name="DNS",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                message=f"RKN DNS spoof detected — {domain} resolves to known stub IP {spoof_ip}",
                details={"ips": ips, "rkn_stub_ip": spoof_ip},
                recommendations=["Use an encrypted DNS resolver (DoH/DoT) to bypass DNS spoofing"],
                duration_ms=dns_ms,
            )
        )
        return diag

    _emit(
        DiagnosticResult(
            check_name="DNS",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=f"Resolved to: {', '.join(ips[:3])}",
            details={"ips": ips},
            duration_ms=dns_ms,
        )
    )

    # --- 2. TCP connectivity ---
    if on_step_start:
        on_step_start("TCP")
    t0 = time.monotonic()
    tcp_ok = False
    tcp_port_used = port

    if await _check_tcp_port(ips[0], port, timeout=timeout):
        tcp_ok = True
    elif port != 80 and await _check_tcp_port(ips[0], 80, timeout=timeout):
        tcp_ok = True
        tcp_port_used = 80

    tcp_ms = (time.monotonic() - t0) * 1000

    if tcp_ok:
        _emit(
            DiagnosticResult(
                check_name="TCP",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"Port {tcp_port_used} reachable on {ips[0]}",
                details={"ip": ips[0], "port": tcp_port_used},
                duration_ms=tcp_ms,
            )
        )
    else:
        _emit(
            DiagnosticResult(
                check_name="TCP",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                message=f"Port {port} (and 80) unreachable on {ips[0]} — IP/TCP blocked",
                details={"ip": ips[0], "port": port},
                recommendations=[
                    f"TCP connection to {domain} is blocked at the IP level",
                    "Try connecting through a proxy or VPN",
                ],
                duration_ms=tcp_ms,
            )
        )

    # --- 3. TCP Ping ---
    if on_step_start:
        on_step_start("TCP Ping")
    ping_result = await _tcp_ping(domain, tcp_port_used, count=3, timeout=timeout)
    _emit(ping_result)

    if not tcp_ok:
        # TLS/HTTP/DPI still worth running (DPI can intercept at connection layer)
        _emit(
            DiagnosticResult(
                check_name="TLS",
                status=CheckStatus.SKIP,
                severity=CheckSeverity.INFO,
                message="Skipped — TCP unreachable",
                duration_ms=0,
            )
        )
        _emit(
            DiagnosticResult(
                check_name="HTTP/HTTPS",
                status=CheckStatus.SKIP,
                severity=CheckSeverity.INFO,
                message="Skipped — TCP unreachable",
                duration_ms=0,
            )
        )
    else:
        # --- 4. TLS ---
        if on_step_start:
            on_step_start("TLS")
        t0 = time.monotonic()
        tls_valid = await _check_certificate(domain, timeout=timeout)
        tls_ms = (time.monotonic() - t0) * 1000

        if tls_valid:
            _emit(
                DiagnosticResult(
                    check_name="TLS",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=f"Certificate valid for {domain}",
                    details={"domain": domain},
                    duration_ms=tls_ms,
                )
            )
        else:
            _emit(
                DiagnosticResult(
                    check_name="TLS",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.WARNING,
                    message=f"Certificate invalid or expired for {domain}",
                    details={"domain": domain},
                    recommendations=["TLS certificate is invalid — possible MITM interception or expired cert"],
                    duration_ms=tls_ms,
                )
            )

        # --- 5. HTTP / HTTPS status ---
        if on_step_start:
            on_step_start("HTTP/HTTPS")
        t0 = time.monotonic()
        http_code, https_code = await asyncio.gather(
            _fetch_http_code(f"http://{domain}", proxy_url=proxy_url, timeout=timeout),
            _fetch_http_code(f"https://{domain}", proxy_url=proxy_url, timeout=timeout),
        )
        http_ms = (time.monotonic() - t0) * 1000

        def _http_ok(code: int) -> bool:
            return 200 <= code < 400

        if _http_ok(http_code) or _http_ok(https_code):
            http_accessible = True
            codes_str = f"HTTP {http_code}" if http_code else ""
            if https_code:
                codes_str += f"{'  ' if codes_str else ''}HTTPS {https_code}"
            _emit(
                DiagnosticResult(
                    check_name="HTTP/HTTPS",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message=f"{domain} is reachable — {codes_str}",
                    details={"http_code": http_code, "https_code": https_code},
                    duration_ms=http_ms,
                )
            )
        elif http_code == 0 and https_code == 0:
            _emit(
                DiagnosticResult(
                    check_name="HTTP/HTTPS",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"No HTTP or HTTPS response from {domain}",
                    details={"http_code": http_code, "https_code": https_code},
                    recommendations=["HTTP/HTTPS traffic is blocked — try a proxy"],
                    duration_ms=http_ms,
                )
            )
        else:
            _emit(
                DiagnosticResult(
                    check_name="HTTP/HTTPS",
                    status=CheckStatus.WARN,
                    severity=CheckSeverity.WARNING,
                    message=f"Unexpected response — HTTP {http_code}, HTTPS {https_code}",
                    details={"http_code": http_code, "https_code": https_code},
                    duration_ms=http_ms,
                )
            )

    # --- 6. DPI (full signal suite) ---
    if on_step_start:
        on_step_start("DPI")
    t0 = time.monotonic()
    sig = await _collect_dpi_signals(domain, ips, timeout=timeout)
    dpi_ms = (time.monotonic() - t0) * 1000

    # Main DPI verdict (aggregate)
    if sig.any_hit():
        dpi_status = CheckStatus.WARN if http_accessible else CheckStatus.FAIL
        dpi_severity = CheckSeverity.WARNING if http_accessible else CheckSeverity.ERROR
        label = _dpi_label(sig)
        dpi_msg = (
            f"{label}: signatures detected for {domain} — site still reachable"
            if http_accessible
            else f"{label}: DPI actively blocking {domain}"
        )
        _emit(
            DiagnosticResult(
                check_name="DPI",
                status=dpi_status,
                severity=dpi_severity,
                message=dpi_msg,
                details={
                    "domain": domain,
                    "label": label,
                    "keyword_hit": sig.keyword_hit,
                    "sni_dummy_hit": sig.sni_dummy_hit,
                    "sni_dummy_fail_ms": sig.sni_dummy_fail_ms,
                    "sni_dummy_fast_rst": sig.sni_dummy_fast_rst,
                    "sni_variance": sig.sni_variance,
                    "fingerprint_variance": sig.fingerprint_variance,
                    "host_header_injection": sig.host_header_injection,
                },
                recommendations=["Deep Packet Inspection (DPI) is active — use a VPN or VLESS/Trojan proxy"],
                duration_ms=dpi_ms,
            )
        )
    else:
        _emit(
            DiagnosticResult(
                check_name="DPI",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message="No DPI blocking detected",
                details={"domain": domain},
                duration_ms=dpi_ms,
            )
        )

    # Sub-probe diagnostics — each one emits its own line so users can see
    # exactly which layer of DPI is active.
    if sig.sni_variance:
        variance_status = CheckStatus.FAIL if sig.sni_variance_suspect else CheckStatus.PASS
        variance_sev = CheckSeverity.ERROR if sig.sni_variance_suspect else CheckSeverity.INFO
        _emit(
            DiagnosticResult(
                check_name="SNI Variance",
                status=variance_status,
                severity=variance_sev,
                message=(
                    f"SNI-based DPI confirmed ({sig.sni_variance})"
                    if sig.sni_variance_suspect
                    else f"No SNI-based DPI ({sig.sni_variance})"
                ),
                details=sig.sni_variance,
                duration_ms=0,
            )
        )

    if sig.fingerprint_variance:
        fp_status = CheckStatus.WARN if sig.fingerprint_variance_suspect else CheckStatus.PASS
        fp_sev = CheckSeverity.WARNING if sig.fingerprint_variance_suspect else CheckSeverity.INFO
        _emit(
            DiagnosticResult(
                check_name="TLS Fingerprint",
                status=fp_status,
                severity=fp_sev,
                message=(
                    f"ClientHello shape matters — {sig.fingerprint_variance}"
                    if sig.fingerprint_variance_suspect
                    else f"Fingerprint-agnostic — {sig.fingerprint_variance}"
                ),
                details=sig.fingerprint_variance,
                recommendations=(
                    ["Use a client with a browser-shaped TLS fingerprint (Xray uTLS, curl-impersonate)"]
                    if sig.fingerprint_variance_suspect
                    else []
                ),
                duration_ms=0,
            )
        )

    if sig.host_header_injection:
        _emit(
            DiagnosticResult(
                check_name="Host-Header DPI",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.ERROR,
                message=f"Plaintext HTTP Host-based DPI injection (code {sig.host_header_code})",
                details={"injected_code": sig.host_header_code},
                duration_ms=0,
            )
        )

    if sig.http3_reachable is not None:
        h3_status = CheckStatus.PASS if sig.http3_reachable else CheckStatus.WARN
        h3_sev = CheckSeverity.INFO if sig.http3_reachable else CheckSeverity.WARNING
        _emit(
            DiagnosticResult(
                check_name="HTTP/3 (QUIC)",
                status=h3_status,
                severity=h3_sev,
                message=(
                    "UDP/443 responds to QUIC — HTTP/3 reachable"
                    if sig.http3_reachable
                    else "No QUIC response on UDP/443 — HTTP/3 filtered or unsupported"
                ),
                details={"reachable": sig.http3_reachable},
                duration_ms=0,
            )
        )

    if sig.doh_ips:
        shared = bool(set(sig.doh_ips) & set(ips))
        if sig.doh_mismatch and not http_accessible:
            # Suspicious IP + site broken → genuine DNS tampering.
            doh_status, doh_sev = CheckStatus.FAIL, CheckSeverity.ERROR
            doh_msg = (
                f"Local DNS points to suspicious IPs {ips} while Cloudflare DoH gives "
                f"{sig.doh_ips}, and the site is unreachable — likely DNS tampering"
            )
            doh_recs = ["DNS responses appear tampered — switch to DoH/DoT (1.1.1.1, 8.8.8.8)"]
        elif sig.doh_mismatch and http_accessible:
            # Suspicious IP but site works → local split-tunnel / FakeDNS (e.g. Xray
            # FakeDNS hands out 198.18.0.0/15 addresses for tunneled domains). Not tampering.
            doh_status, doh_sev = CheckStatus.PASS, CheckSeverity.INFO
            doh_msg = (
                f"Local DNS returns a synthetic IP {ips} (DoH: {sig.doh_ips}) but the site "
                "is reachable — looks like local FakeDNS/split-tunnel (e.g. Xray FakeDNS), not tampering"
            )
            doh_recs = []
        elif shared:
            doh_status, doh_sev = CheckStatus.PASS, CheckSeverity.INFO
            doh_msg = f"Local DNS matches Cloudflare DoH (DoH: {sig.doh_ips[:3]})"
            doh_recs = []
        else:
            # Different IPs but local ones are not suspicious — normal CDN/anycast variance.
            doh_status, doh_sev = CheckStatus.PASS, CheckSeverity.INFO
            doh_msg = (
                f"Local DNS and Cloudflare DoH return different IPs ({ips} vs {sig.doh_ips}) — "
                "likely CDN/anycast variance, not tampering"
            )
            doh_recs = []
        _emit(
            DiagnosticResult(
                check_name="DoH Cross-check",
                status=doh_status,
                severity=doh_sev,
                message=doh_msg,
                details={"doh_ips": sig.doh_ips, "local_ips": ips, "mismatch": sig.doh_mismatch},
                recommendations=doh_recs,
                duration_ms=0,
            )
        )

    # --- 7. AI/regional blocking (selected domains only) ---
    if domain in AI_REGIONAL_DOMAINS:
        if on_step_start:
            on_step_start("Regional Block")
        t0 = time.monotonic()
        regional = await _check_ai_regional_blocking(domain, timeout=timeout, proxy_url=proxy_url)
        reg_ms = (time.monotonic() - t0) * 1000

        if regional:
            _emit(
                DiagnosticResult(
                    check_name="Regional Block",
                    status=CheckStatus.FAIL,
                    severity=CheckSeverity.ERROR,
                    message=f"{domain} shows regional blocking message",
                    details={"domain": domain},
                    recommendations=["Regional access restriction detected — use a non-Russian exit node"],
                    duration_ms=reg_ms,
                )
            )
        else:
            _emit(
                DiagnosticResult(
                    check_name="Regional Block",
                    status=CheckStatus.PASS,
                    severity=CheckSeverity.INFO,
                    message="No regional blocking detected",
                    duration_ms=reg_ms,
                )
            )

    return diag


async def _fetch_raw_domain_list(url: str, label: str) -> list[str]:
    """Download a plain-text domain list (one domain per line, # comments stripped)."""
    log.info("Fetching domain list", label=label, url=url)
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.get(
                url,
                timeout=ClientTimeout(total=30),
            ) as response,
        ):
            if response.status != 200:
                log.error("Failed to fetch domain list", label=label, http_status=response.status)
                return []
            text = await response.text()

        domains = []
        for raw_line in text.splitlines():
            domain = raw_line.strip().lstrip(".")
            if domain and not domain.startswith("#"):
                domains.append(domain)

        log.info("Fetched domain list", label=label, domain_count=len(domains))
        return domains
    except Exception as e:
        log.error("Error fetching domain list", label=label, error=str(e))
        return []


async def fetch_whitelist_domains() -> list[str]:
    """Fetch domain list from russia-mobile-internet-whitelist GitHub repo."""
    return await _fetch_raw_domain_list(WHITELIST_URL, "whitelist")


async def fetch_allow_domains_list(list_name: str) -> list[str]:
    """Fetch a named list from itdoginfo/allow-domains on GitHub.

    Args:
        list_name: One of the keys in ALLOW_DOMAINS_LISTS
                   ('russia-inside', 'russia-outside', 'ukraine-inside').

    Returns:
        List of domain strings, or empty list on failure.
    """
    if list_name not in ALLOW_DOMAINS_LISTS:
        raise ValueError(f"Unknown list '{list_name}'. Available: {', '.join(ALLOW_DOMAINS_LISTS)}")
    url, label = ALLOW_DOMAINS_LISTS[list_name]
    return await _fetch_raw_domain_list(url, label)


async def run_censor_check(
    domains: list[str] | None = None,
    proxy_url: str = "",
    timeout: int = 4,
    max_parallel: int = 10,
    on_domain_complete: Callable[[DomainCheckResult], None] | None = None,
) -> CensorCheckSummary:
    """
    Run censor-check on a list of domains.

    Args:
        on_domain_complete: Optional callback invoked after each domain finishes.
            Called synchronously from the async task, so keep it fast (no awaits).
    """
    if domains is None:
        domains = DEFAULT_CENSOR_DOMAINS

    log.info(
        "Starting censor-check",
        domain_count=len(domains),
        proxy=proxy_url or "direct",
        max_parallel=max_parallel,
    )

    start_time = time.time()
    semaphore = asyncio.Semaphore(max_parallel)

    async def _check_with_semaphore(domain: str) -> DomainCheckResult:
        async with semaphore:
            result = await check_domain(domain, proxy_url=proxy_url, timeout=timeout)
            if on_domain_complete is not None:
                on_domain_complete(result)
            return result

    # Run checks in parallel
    tasks = [_check_with_semaphore(domain) for domain in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    valid_results: list[DomainCheckResult] = []
    for r in results:
        if isinstance(r, Exception):
            log.error("Censor-check task failed", error=str(r))
            continue
        if isinstance(r, DomainCheckResult):
            valid_results.append(r)

    duration = time.time() - start_time

    # Count statistics
    ok_count = sum(1 for r in valid_results if r.status == DomainStatus.OK)
    blocked_count = sum(1 for r in valid_results if r.status == DomainStatus.BLOCKED)
    partial_count = sum(1 for r in valid_results if r.status == DomainStatus.PARTIAL)

    summary = CensorCheckSummary(
        total=len(valid_results),
        ok=ok_count,
        blocked=blocked_count,
        partial=partial_count,
        results=valid_results,
        duration_seconds=duration,
        proxy_url=proxy_url,
    )

    log.info(
        "Censor-check complete",
        ok=ok_count,
        blocked=blocked_count,
        partial=partial_count,
        duration_s=round(duration, 1),
    )

    return summary
