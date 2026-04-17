"""DNS diagnostic checks."""

import asyncio
import socket
from ipaddress import ip_address, ip_network
from typing import Any

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("dns_checker")

CHECK_HOST_BASE_URL = "https://check-host.net"


# Shared session for Check-Host API calls — avoids spinning up a new TCP pool
# on every parallel DNS check. Created lazily, closed via close_dns_session().
class _SessionHolder:
    session: aiohttp.ClientSession | None = None


def _get_checkhost_session() -> aiohttp.ClientSession:
    if _SessionHolder.session is None or _SessionHolder.session.closed:
        _SessionHolder.session = aiohttp.ClientSession()
    return _SessionHolder.session


async def close_dns_session() -> None:
    """Close the shared Check-Host session. Call on app shutdown."""
    if _SessionHolder.session is not None and not _SessionHolder.session.closed:
        await _SessionHolder.session.close()
    _SessionHolder.session = None


# Xray FakeDNS address pools — virtual IPs assigned by Xray's transparent DNS proxy.
# These never exist on the real internet, so comparing them against Check-Host is meaningless.
# https://xtls.github.io/ru/config/fakedns.html
FAKEDNS_NETWORKS = [
    ip_network("198.18.0.0/15"),  # default IPv4 FakeDNS pool
    ip_network("fc00::/18"),  # default IPv6 FakeDNS pool
]


def is_fakedns_ip(addr: str) -> bool:
    """Return True if *addr* belongs to Xray FakeDNS virtual address pools."""
    try:
        parsed = ip_address(addr)
        return any(parsed in net for net in FAKEDNS_NETWORKS)
    except ValueError:
        return False


async def check_dns_with_checkhost(host: str) -> DiagnosticResult:
    """
    Check DNS resolution using both local resolver and Check-Host.net API.

    Compares local DNS resolution with results from Check-Host.net
    to detect DNS poisoning or geo-specific blocking.

    Check-Host.net API: https://check-host.net/about/api
    - Init: GET /check-dns?host=<HOST>&max_nodes=3
    - Result: GET /check-result/<REQUEST_ID>
    """
    loop = asyncio.get_running_loop()
    start_time = loop.time()
    log.debug("Checking DNS resolution with Check-Host.net comparison", host=host)

    # Run local DNS and Check-Host concurrently
    local_task = asyncio.create_task(_local_dns_resolve(host))
    checkhost_task = asyncio.create_task(_checkhost_dns_resolve(host))

    try:
        local_result, checkhost_result = await asyncio.gather(local_task, checkhost_task, return_exceptions=False)
    except Exception:
        local_task.cancel()
        checkhost_task.cancel()
        raise

    duration_ms = (loop.time() - start_time) * 1000

    # Build details
    details: dict[str, Any] = {
        "host": host,
        "local_ips": local_result.get("ips", []),
        "checkhost_ips": checkhost_result.get("ips", []),
        "duration_ms": round(duration_ms, 2),
    }

    local_success = local_result.get("success", False)
    checkhost_success = checkhost_result.get("success", False)

    # FakeDNS detection: local resolver returns virtual IPs from Xray FakeDNS pool.
    # These IPs are never real internet addresses, so the mismatch with Check-Host
    # is expected and harmless — Xray intercepts traffic by the fake IP anyway.
    local_ips_raw = local_result.get("ips", [])
    fakedns_ips = [ip for ip in local_ips_raw if is_fakedns_ip(ip)]
    if fakedns_ips:
        details["fakedns_ips"] = fakedns_ips
        details["checkhost_ips"] = checkhost_result.get("ips", [])
        log.info("FakeDNS virtual IPs detected", host=host, fakedns_ips=fakedns_ips)
        return DiagnosticResult(
            check_name="DNS Resolution (Check-Host)",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=(
                f"DNS for {host}: Xray FakeDNS detected "
                f"(virtual IPs: {', '.join(fakedns_ips)}) — mismatch with Check-Host is expected"
            ),
            details=details,
        )

    # If Check-Host failed, report based on local result only
    if not checkhost_success:
        checkhost_error = checkhost_result.get("error", "Check-Host API error")
        checkhost_api_flaky = checkhost_result.get("api_unavailable", False)
        details["checkhost_error"] = checkhost_error
        details["checkhost_api_unavailable"] = checkhost_api_flaky

        if local_success:
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"DNS resolved successfully for {host} (Check-Host unavailable)",
                details=details,
            )
        else:
            # When Check-Host API is flaky AND local DNS failed, don't hard-fail:
            # a transient resolver glitch is a weak signal — TCP / proxy checks will
            # tell us if the server is actually unreachable. Surface as WARN instead.
            local_err = local_result.get("error") or "resolver returned no records"
            if checkhost_api_flaky:
                return DiagnosticResult(
                    check_name="DNS Resolution (Check-Host)",
                    status=CheckStatus.WARN,
                    severity=CheckSeverity.WARNING,
                    message=(
                        f"DNS for {host} did not resolve locally and Check-Host is unavailable "
                        f"({local_err}) — verify via TCP / proxy instead"
                    ),
                    details=details,
                )
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                message=f"DNS resolution failed for {host}: {local_err}",
                details=details,
                recommendations=[
                    "Check DNS server settings in /etc/resolv.conf",
                    "Try using public DNS (8.8.8.8, 1.1.1.1)",
                ],
            )

    # Compare IPs
    local_ips = set(local_ips_raw)
    checkhost_ips = set(checkhost_result.get("ips", []))

    common_ips = local_ips & checkhost_ips
    local_only = local_ips - checkhost_ips
    checkhost_only = checkhost_ips - local_ips

    details.update(
        {
            "common_ips": list(common_ips),
            "local_only_ips": list(local_only),
            "checkhost_only_ips": list(checkhost_only),
            "ip_match": len(common_ips) > 0,
        }
    )

    # Determine status
    if local_success and checkhost_success:
        if len(common_ips) > 0:
            # IPs match - all good
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"DNS resolved successfully for {host}, IPs match with Check-Host",
                details=details,
            )
        else:
            # No common IPs — can be CDN geo-routing (Cloudflare, Fastly, etc.),
            # Anycast, or actual DNS poisoning. Local DNS resolves, so it's not
            # a failure — surface as INFO, not a blocking indicator.
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=(
                    f"DNS for {host}: local IPs differ from Check-Host "
                    f"(normal for CDN/Anycast; may indicate DNS poisoning if proxy fails)"
                ),
                details=details,
            )
    elif not local_success and checkhost_success:
        # Local DNS fails but Check-Host resolves the domain. This is expected
        # when the host is running inside an Xray FakeDNS / split-DNS setup
        # where the local resolver does not see real Internet records — the
        # proxy path handles resolution. Surface as WARN (not FAIL) so it
        # doesn't mask the authoritative proxy/TCP results.
        return DiagnosticResult(
            check_name="DNS Resolution (Check-Host)",
            status=CheckStatus.WARN,
            severity=CheckSeverity.INFO,
            message=(
                f"Local DNS cannot resolve {host}, but Check-Host does — "
                f"likely FakeDNS / split-DNS (not a failure if the proxy path works)"
            ),
            details=details,
        )
    else:
        # Both fail
        return DiagnosticResult(
            check_name="DNS Resolution (Check-Host)",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"DNS cannot resolve {host} locally or through Check-Host",
            details=details,
            recommendations=[
                "Domain not resolved locally or through Check-Host.net",
                "Check the domain name spelling",
                "Make sure the domain is registered and active",
            ],
        )


async def _local_dns_resolve(host: str) -> dict[str, Any]:
    """Resolve host using local DNS."""
    try:
        loop = asyncio.get_running_loop()
        addr_infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=settings.dns_timeout,
        )

        resolved_ips: list[str] = []
        for _family, _, _, _, sockaddr in addr_infos:
            ip = sockaddr[0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        return {"success": True, "ips": resolved_ips}
    except (socket.gaierror, TimeoutError, OSError) as e:
        return {"success": False, "error": str(e)}


async def _checkhost_dns_resolve(host: str) -> dict[str, Any]:
    """
    Resolve host using Check-Host.net API.

    Two-step process:
    1. Init check: GET /check-dns?host=<HOST>&max_nodes=3
    2. Poll result: GET /check-result/<REQUEST_ID>
    """
    headers = {"Accept": "application/json"}
    session = _get_checkhost_session()

    # Step 1: Init DNS check
    init_url = f"{CHECK_HOST_BASE_URL}/check-dns"
    params = {"host": host, "max_nodes": 3}

    try:
        async with session.get(
            init_url,
            params=params,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:
            if response.status != 200:
                return {
                    "success": False,
                    "error": f"Check-Host init failed: HTTP {response.status}",
                    "api_unavailable": True,
                }

            init_data = await response.json()

            if not init_data.get("ok"):
                return {
                    "success": False,
                    "error": f"Check-Host returned error: {init_data}",
                    "api_unavailable": True,
                }

            request_id = init_data.get("request_id")
            if not request_id:
                return {
                    "success": False,
                    "error": "No request_id in Check-Host response",
                    "api_unavailable": True,
                }

    except aiohttp.ClientError as e:
        return {"success": False, "error": f"Check-Host HTTP error: {e}", "api_unavailable": True}
    except TimeoutError:
        return {"success": False, "error": "Check-Host init timed out", "api_unavailable": True}

    # Step 2: Poll for results (up to 15 seconds)
    result_url = f"{CHECK_HOST_BASE_URL}/check-result/{request_id}"
    max_polls = 15
    poll_delay = 1

    for _ in range(max_polls):
        try:
            await asyncio.sleep(poll_delay)

            async with session.get(
                result_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    return {
                        "success": False,
                        "error": f"Check-Host result failed: HTTP {response.status}",
                        "api_unavailable": True,
                    }

                result_data = await response.json()

                # Check if any node has completed
                all_ips: list[str] = []
                all_done = False
                has_pending = False

                for _node_id, node_result in result_data.items():
                    if node_result is None:
                        has_pending = True
                        continue

                    all_done = True
                    # DNS result format: [{"A": [...], "AAAA": [...], "TTL": ...}]
                    if isinstance(node_result, list) and len(node_result) > 0:
                        dns_data = node_result[0]
                        if isinstance(dns_data, dict):
                            a_records = dns_data.get("A", [])
                            aaaa_records = dns_data.get("AAAA", [])
                            all_ips.extend(a_records)
                            all_ips.extend(aaaa_records)

                if all_done and all_ips:
                    # Deduplicate preserving order
                    seen: set[str] = set()
                    unique_ips = []
                    for ip in all_ips:
                        if ip not in seen:
                            seen.add(ip)
                            unique_ips.append(ip)
                    return {"success": True, "ips": unique_ips}

                if not has_pending and not all_ips:
                    # All nodes returned empty payloads — Check-Host is often flaky
                    # under load and reports empty even for resolvable domains. Treat
                    # this as API unavailability rather than a domain-level failure.
                    return {
                        "success": False,
                        "error": "Check-Host nodes returned empty — API may be flaky",
                        "api_unavailable": True,
                    }

                # Return early if we have any IPs even with some nodes still pending
                if all_ips:
                    seen = set()
                    unique_ips = []
                    for ip in all_ips:
                        if ip not in seen:
                            seen.add(ip)
                            unique_ips.append(ip)
                    return {"success": True, "ips": unique_ips}

        except (aiohttp.ClientError, TimeoutError):
            continue

    return {"success": False, "error": "Check-Host result polling timed out", "api_unavailable": True}
