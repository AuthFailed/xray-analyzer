"""Censor-check: Test web resources through proxy for blocking/censorship detection.

This module replicates the behavior of the bash script by Nikola Tesla
(https://t.me/tracerlab) exactly, with all checks implemented the same way.
"""

import asyncio
import contextlib
import re
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import aiohttp
from aiohttp import ClientTimeout

from xray_analyzer.core.logger import get_logger

log = get_logger("censor_checker")

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
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Safari/605.1.15"
)

SNI_DUMMY_IP = "192.0.2.1"  # Dummy IP for SNI test (from bash script)


class DomainStatus(StrEnum):
    """Status of domain check."""

    OK = "OK"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"


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
        log.debug(f"DNS resolution failed for {domain}: {e}")
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
        return await _fetch_with_curl(
            url, proxy_url, timeout, retries, user_agent, extra_headers, resolve_to_ip
        )

    for attempt in range(retries):
        async with aiohttp.ClientSession() as session:
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
                log.debug(f"HTTP fetch failed for {url} (attempt {attempt + 1}/{retries}): {e}")
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
        "-o", "/dev/null",
        "--retry", str(retries),
        "--connect-timeout", str(timeout),
        "--max-time", str(timeout),
        "-4",  # IPv4 only
        "-A", user_agent,
        "-w", "%{http_code}",
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
            log.debug(f"Curl failed for {url} (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                await asyncio.sleep(0.5)
                continue

    return 0


async def _check_certificate(domain: str, timeout: int = 4, verbose: bool = False) -> bool:
    """
    Check TLS certificate using openssl s_client (exactly like bash script).

    Equivalent to:
    timeout 4 openssl s_client -connect "$domain:443" -servername "$domain"
      -CApath /etc/ssl/certs -verify 5
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "timeout", str(timeout),
            "openssl", "s_client",
            "-connect", f"{domain}:443",
            "-servername", domain,
            "-CApath", "/etc/ssl/certs",
            "-verify", "5",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(input=b"")
        cert_info = (stdout + stderr).decode()

        # Check for verification errors
        if "Verification error:" in cert_info or "Verification: OK" not in cert_info:
            if verbose:
                log.info(f"TLS verification failed for {domain}")
            return False

        # Extract expiration date
        not_after_match = re.search(r"notAfter=(.+)", cert_info)
        if not_after_match:
            not_after_str = not_after_match.group(1).strip()
            # Check if certificate is expired
            try:
                # Use date command to parse
                date_proc = await asyncio.create_subprocess_exec(
                    "date", "-d", not_after_str, "+%s",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                date_stdout, _ = await date_proc.communicate()
                expire_epoch = int(date_stdout.decode().strip())
                current_epoch = int(time.time())

                if expire_epoch < current_epoch:
                    if verbose:
                        log.info(f"Certificate expired for {domain}")
                    return False
            except (ValueError, Exception):
                pass

        return True
    except Exception as e:
        log.debug(f"Certificate check failed for {domain}: {e}")
        return False


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


async def _check_dpi_blocking(domain: str, timeout: int = 4) -> bool:
    """
    Check if domain is blocked by DPI (exactly like bash script).

    Method 1: Check response with suspicious User-Agent for blocking keywords
    Method 2: SNI test - resolve domain to dummy IP 192.0.2.1, check if we get 4xx/5xx/000
    """
    test_url = f"https://{domain}"

    # Method 1: Check response body for blocking keywords
    try:
        headers = {"User-Agent": "Suspicious-Agent TLS/1.3"}
        async with aiohttp.ClientSession() as session, session.get(
            test_url,
            timeout=ClientTimeout(connect=timeout, total=timeout),
            headers=headers,
            ssl=True,
        ) as response:
            text = await response.text()
            if any(pattern.search(text) for pattern in DPI_BLOCKING_KEYWORDS):
                return True
    except Exception:
        pass

    # Method 2: SNI test with dummy IP (like bash: curl --resolve "$domain:443:192.0.2.1")
    try:
        sni_code = await _fetch_with_curl(
            test_url,
            timeout=timeout,
            retries=1,
            user_agent=USER_AGENT,
            resolve_to_ip=SNI_DUMMY_IP,
        )

        # If we get 4xx/5xx or 000, DPI is likely intercepting
        if sni_code == 0 or (400 <= sni_code < 600):
            return True
    except Exception:
        # Connection failure might indicate DPI blocking
        pass

    return False


async def _check_ai_regional_blocking(domain: str, timeout: int = 4) -> bool:
    """
    Check if AI/social domain has regional blocking (exactly like bash script).
    """
    try:
        # Use curl to get response (supports --compressed like bash)
        curl_cmd = [
            "curl",
            "-s",
            "-A", USER_AGENT,
            "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.5",
            "-H", "Upgrade-Insecure-Requests: 1",
            "-H", "Sec-Fetch-Dest: document",
            "-H", "Sec-Fetch-Mode: navigate",
            "-H", "Sec-Fetch-Site: none",
            "-H", "Sec-Fetch-User: ?1",
            "-H", "Connection: keep-alive",
            "--compressed",
            "--connect-timeout", str(timeout),
            f"https://{domain}",
        ]

        proc = await asyncio.create_subprocess_exec(
            *curl_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        response_text = stdout.decode()

        # Check for regional blocking
        if any(pattern.search(response_text) for pattern in AI_BLOCKING_KEYWORDS):
            return True

        # Check for Cloudflare challenge (not blocking)
        if any(pattern.search(response_text) for pattern in CLOUDFLARE_CHALLENGE_KEYWORDS):
            return False

        return False
    except Exception:
        return False


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

    # 4. TLS certificate check (like bash: openssl s_client)
    tls_valid = await _check_certificate(domain, timeout=timeout)
    result.tls_valid = tls_valid

    if not tls_valid:
        result.block_type = "TLS/SSL"

    # 5. HTTP/HTTPS connectivity check (like bash: fetch_code)
    http_code = await _fetch_http_code(
        f"http://{domain}",
        proxy_url=proxy_url,
        timeout=timeout,
        retries=2,
    )
    https_code = await _fetch_http_code(
        f"https://{domain}",
        proxy_url=proxy_url,
        timeout=timeout,
        retries=2,
    )

    result.http_code = http_code
    result.https_code = https_code

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

    # 6. DPI check (like bash: check_keyword_blocking)
    if await _check_dpi_blocking(domain, timeout=timeout):
        if result.block_type:
            result.block_type = f"{result.block_type}/DPI"
        else:
            result.block_type = "DPI/KEYWORD"

    # 7. AI/Social regional blocking check (like bash: if [[ " ${AI_DOMAINS[*]} " =~ " ${domain} " ]])
    if domain in AI_REGIONAL_DOMAINS and await _check_ai_regional_blocking(domain, timeout=timeout):
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

    return result


async def run_censor_check(
    domains: list[str] | None = None,
    proxy_url: str = "",
    timeout: int = 4,
    max_parallel: int = 10,
) -> CensorCheckSummary:
    """
    Run censor-check on a list of domains.
    """
    if domains is None:
        domains = DEFAULT_CENSOR_DOMAINS

    log.info(f"Starting censor-check for {len(domains)} domains (proxy: {proxy_url or 'direct'})")

    start_time = time.time()
    semaphore = asyncio.Semaphore(max_parallel)

    async def _check_with_semaphore(domain: str) -> DomainCheckResult:
        async with semaphore:
            return await check_domain(domain, proxy_url=proxy_url, timeout=timeout)

    # Run checks in parallel
    tasks = [_check_with_semaphore(domain) for domain in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    valid_results: list[DomainCheckResult] = []
    for r in results:
        if isinstance(r, Exception):
            log.error(f"Censor-check task failed: {r}")
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
        f"Censor-check complete: {ok_count} OK, {blocked_count} BLOCKED, "
        f"{partial_count} PARTIAL in {duration:.1f}s"
    )

    return summary
