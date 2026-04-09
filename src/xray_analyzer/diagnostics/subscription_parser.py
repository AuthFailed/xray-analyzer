"""Parse subscription URLs to extract VLESS/Trojan/Shadowsocks share URLs."""

import base64
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp

from xray_analyzer.core.logger import get_logger

log = get_logger("subscription_parser")


@dataclass
class ProxyShareURL:
    """Parsed proxy share URL from subscription."""

    protocol: str  # vless, trojan, ss, http, socks
    name: str
    server: str
    port: int
    raw_url: str  # Original share URL
    params: dict[str, Any] = field(default_factory=dict)

    # Protocol-specific fields
    uuid: str = ""
    password: str = ""
    method: str = ""  # SS encryption method
    flow: str = ""
    sni: str = ""
    network: str = "tcp"
    path: str = ""
    host: str = ""
    service_name: str = ""
    security: str = "none"
    fp: str = ""
    pbk: str = ""
    sid: str = ""
    spx: str = ""


def decode_subscription(text: str) -> str:
    """
    Decode base64 subscription content.

    Subscription URLs return base64-encoded share URLs, one per line.
    Some may already be decoded, so we try decoding first.
    """
    # Try base64 decode
    try:
        # Add padding if needed
        padded = text + "=" * (4 - len(text) % 4) if len(text) % 4 else text
        decoded = base64.b64decode(padded).decode("utf-8")
        # Check if decoded content has share URLs
        if any(decoded.startswith(p) for p in ("vless://", "trojan://", "ss://", "http://", "socks://")):
            return decoded
    except Exception:
        pass

    # Return as-is if not base64
    return text


def parse_vless_url(url: str) -> ProxyShareURL:
    """Parse a VLESS share URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    def _get(key: str, default: str = "") -> str:
        values = params.get(key, [default])
        return values[0] if values else default

    return ProxyShareURL(
        protocol="vless",
        name=unquote(parsed.fragment or ""),
        server=parsed.hostname or "",
        port=int(parsed.port or 0),
        raw_url=url,
        uuid=parsed.username or "",
        flow=_get("flow"),
        sni=_get("sni"),
        network=_get("type", "tcp"),
        path=_get("path"),
        host=_get("host"),
        service_name=_get("serviceName"),
        security=_get("security", "none"),
        fp=_get("fp"),
        pbk=_get("pbk"),
        sid=_get("sid"),
        spx=_get("spx"),
        params={k: v[0] if len(v) == 1 else v for k, v in params.items()},
    )


def parse_trojan_url(url: str) -> ProxyShareURL:
    """Parse a Trojan share URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    def _get(key: str, default: str = "") -> str:
        values = params.get(key, [default])
        return values[0] if values else default

    return ProxyShareURL(
        protocol="trojan",
        name=unquote(parsed.fragment or ""),
        server=parsed.hostname or "",
        port=int(parsed.port or 0),
        raw_url=url,
        password=parsed.username or "",
        sni=_get("sni"),
        network=_get("type", "tcp"),
        path=_get("path"),
        host=_get("host"),
        service_name=_get("serviceName"),
        security=_get("security", "tls"),
        params={k: v[0] if len(v) == 1 else v for k, v in params.items()},
    )


def parse_ss_url(url: str) -> ProxyShareURL:
    """Parse a Shadowsocks share URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    def _get(key: str, default: str = "") -> str:
        values = params.get(key, [default])
        return values[0] if values else default

    # Decode userinfo part (method:password@host or method:password)
    userinfo = parsed.username or ""
    try:
        # Some SS URLs encode the userinfo in base64
        decoded = base64.urlsafe_b64decode(userinfo + "==").decode("utf-8")
        parts = decoded.split(":", 1)
        method = parts[0]
        password = parts[1] if len(parts) > 1 else ""
    except Exception:
        method = userinfo
        password = parsed.password or ""

    return ProxyShareURL(
        protocol="ss",
        name=unquote(parsed.fragment or ""),
        server=parsed.hostname or "",
        port=int(parsed.port or 0),
        raw_url=url,
        method=method,
        password=password,
        params={k: v[0] if len(v) == 1 else v for k, v in params.items()},
    )


def parse_share_url(url: str) -> ProxyShareURL | None:
    """Parse a single share URL."""
    url = url.strip()
    if not url:
        return None

    try:
        scheme = url.split("://", 1)[0].lower()
        if scheme == "vless":
            return parse_vless_url(url)
        elif scheme == "trojan":
            return parse_trojan_url(url)
        elif scheme == "ss":
            return parse_ss_url(url)
        elif scheme in ("http", "https", "socks", "socks5", "socks5h", "socks4"):
            parsed = urlparse(url)
            return ProxyShareURL(
                protocol=scheme,
                name=unquote(parsed.fragment or parsed.netloc),
                server=parsed.hostname or "",
                port=int(parsed.port or 0),
                raw_url=url,
            )
        else:
            log.debug(f"Unknown protocol in share URL: {scheme}")
            return None
    except Exception as e:
        log.warning(f"Failed to parse share URL: {e}")
        return None


async def fetch_subscription(
    url: str,
    hwid: str = "",
) -> list[ProxyShareURL]:
    """
    Fetch and parse a subscription URL.

    Args:
        url: Subscription URL
        hwid: HWID to send as x-hwid header (required for some providers)

    Returns list of parsed proxy share URLs.
    """
    log.info(f"Fetching subscription from {url}")

    headers = {"User-Agent": "v2rayN/6.33"}
    if hwid:
        headers["x-hwid"] = hwid
        log.debug(f"Using HWID: {hwid[:8]}...")

    async with (
        aiohttp.ClientSession() as session,
        session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as response,
    ):
        if response.status != 200:
            log.error(f"Failed to fetch subscription: HTTP {response.status}")
            return []

        raw_text = await response.text()

    decoded = decode_subscription(raw_text)
    lines = decoded.strip().split("\n")

    proxies = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        share = parse_share_url(line)
        if share:
            proxies.append(share)

    log.info(f"Fetched {len(proxies)} proxies from subscription")
    return proxies


def _normalize_name(name: str) -> str:
    """Remove emojis and whitespace for comparison."""
    return re.sub(r"[\U00010000-\U0010ffff\s]", "", name).strip().lower()


def find_share_url_for_proxy(
    shares: list[ProxyShareURL],
    server: str,
    port: int,
    protocol: str,
    name: str = "",
) -> ProxyShareURL | None:
    """
    Find a matching share URL for a proxy from the checker API.

    Tries multiple matching strategies in order of specificity:
    1. Exact: server + port + protocol
    2. Server match: server + protocol (port may differ)
    3. Name match: proxy name ≈ share URL fragment (emoji-stripped)
    4. Protocol + same subscription group (loose)
    """
    _log = log.bind(new_logger="share_matcher")
    _log.debug(f"Looking for share: server={server}:{port}, proto={protocol}, name={name}")

    norm_name = _normalize_name(name) if name else ""
    _log.debug(f"Available shares: {[(s.server, s.port, s.protocol, s.name) for s in shares]}")

    # 1. Exact match: server + port + protocol
    for share in shares:
        if share.server == server and share.port == port and share.protocol.lower() == protocol.lower():
            _log.debug(f"Match #1 (exact): {share.name}")
            return share

    # 2. Server + protocol (port may differ)
    for share in shares:
        if share.server == server and share.protocol.lower() == protocol.lower():
            _log.debug(f"Match #2 (server+proto): {share.name}")
            return share

    # 3. Name match (strip emojis from both names)
    if norm_name:
        for share in shares:
            share_norm = _normalize_name(share.name)
            if share_norm and share_norm == norm_name:
                _log.debug(f"Match #3 exact name: {share.name}")
                return share
            # Partial: share name is contained in proxy name or vice versa
            if share_norm and norm_name and (share_norm in norm_name or norm_name in share_norm):
                _log.debug(f"Match #3 partial name: {share.name} in {name}")
                return share

    # 4. Same protocol + same server
    for share in shares:
        if share.protocol.lower() == protocol.lower() and share.server == server:
            _log.debug(f"Match #4 (server+proto fallback): {share.name}")
            return share

    # 5. Last resort: same protocol + port within 10
    for share in shares:
        if share.protocol.lower() == protocol.lower() and abs(share.port - port) <= 10:
            _log.debug(f"Match #5 (port range): {share.name}")
            return share

    if shares:
        _log.warning(
            f"No share found for {server}:{port} ({protocol}, name='{name}'). "
            f"Available: {[(s.server, s.port, s.protocol, s.name) for s in shares]}"
        )
    else:
        _log.debug(
            f"No shares available for {server}:{port} ({protocol}, name='{name}'). "
            f"Subscription is empty or contains only placeholders."
        )
    return None
