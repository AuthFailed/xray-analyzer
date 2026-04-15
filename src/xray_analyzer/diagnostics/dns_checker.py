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

# Xray FakeDNS address pools — virtual IPs assigned by Xray's transparent DNS proxy.
# These never exist on the real internet, so comparing them against Check-Host is meaningless.
# https://xtls.github.io/ru/config/fakedns.html
_FAKEDNS_NETWORKS = [
    ip_network("198.18.0.0/15"),  # default IPv4 FakeDNS pool
    ip_network("fc00::/18"),  # default IPv6 FakeDNS pool
]


def _is_fakedns_ip(addr: str) -> bool:
    """Return True if *addr* belongs to Xray FakeDNS virtual address pools."""
    try:
        parsed = ip_address(addr)
        return any(parsed in net for net in _FAKEDNS_NETWORKS)
    except ValueError:
        return False


async def check_dns_resolution(host: str) -> DiagnosticResult:
    """
    Check if a host can be resolved via local DNS.

    Returns a DiagnosticResult with status and resolved IPs.
    """
    loop = asyncio.get_running_loop()
    start_time = loop.time()
    log.debug("Checking DNS resolution", host=host)

    try:
        addr_infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=settings.dns_timeout,
        )

        resolved_ips: list[str] = []
        for _family, _, _, _, sockaddr in addr_infos:
            ip = sockaddr[0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        duration_ms = (loop.time() - start_time) * 1000
        log.info("DNS resolution successful", host=host, ips=resolved_ips, duration_ms=round(duration_ms, 2))

        return DiagnosticResult(
            check_name="DNS Resolution",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=f"DNS resolved successfully for {host}",
            details={
                "resolved_ips": resolved_ips,
                "address_count": len(resolved_ips),
                "duration_ms": round(duration_ms, 2),
            },
        )

    except socket.gaierror as e:
        duration_ms = (loop.time() - start_time) * 1000
        error_msg = str(e)
        log.error("DNS resolution failed", host=host, error=error_msg)

        return DiagnosticResult(
            check_name="DNS Resolution",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"DNS resolution failed for {host}: {error_msg}",
            details={
                "error_code": e.errno,
                "error_str": error_msg,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Check the domain name spelling",
                "Check DNS server settings in /etc/resolv.conf",
                "Try using public DNS (8.8.8.8, 1.1.1.1)",
            ],
        )

    except TimeoutError:
        duration_ms = (loop.time() - start_time) * 1000
        log.error("DNS resolution timed out", host=host)

        return DiagnosticResult(
            check_name="DNS Resolution",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"DNS resolution timed out for {host} ({settings.dns_timeout}s)",
            details={
                "timeout_seconds": settings.dns_timeout,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Check DNS server settings in /etc/resolv.conf",
                "Make sure the DNS server is accessible",
                "Try using public DNS (8.8.8.8, 1.1.1.1)",
            ],
        )


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
    fakedns_ips = [ip for ip in local_ips_raw if _is_fakedns_ip(ip)]
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
        details["checkhost_error"] = checkhost_error

        if local_success:
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"DNS resolved successfully for {host} (Check-Host unavailable)",
                details=details,
            )
        else:
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                message=f"DNS resolution failed for {host}: {local_result.get('error', 'unknown')}",
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
            # No common IPs - possible DNS poisoning or geo-blocking
            # Local DNS resolves, so it's not a failure — just a geo-blocking indicator
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.PASS,
                severity=CheckSeverity.WARNING,
                message=(f"DNS for {host}: local IPs don't match Check-Host (possible DNS poisoning or geo-blocking)"),
                details=details,
            )
    elif not local_success and checkhost_success:
        # Local DNS fails but Check-Host resolves - DNS issue
        return DiagnosticResult(
            check_name="DNS Resolution (Check-Host)",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Local DNS cannot resolve {host}, but Check-Host resolves it (DNS issue)",
            details=details,
            recommendations=[
                "Check-Host.net resolves the domain, but local DNS does not",
                "Check DNS server settings in /etc/resolv.conf",
                "Try using public DNS (8.8.8.8, 1.1.1.1)",
            ],
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

    async with aiohttp.ClientSession() as session:
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
                    return {"success": False, "error": f"Check-Host init failed: HTTP {response.status}"}

                init_data = await response.json()

                if not init_data.get("ok"):
                    return {"success": False, "error": f"Check-Host returned error: {init_data}"}

                request_id = init_data.get("request_id")
                if not request_id:
                    return {"success": False, "error": "No request_id in Check-Host response"}

        except aiohttp.ClientError as e:
            return {"success": False, "error": f"Check-Host HTTP error: {e}"}
        except TimeoutError:
            return {"success": False, "error": "Check-Host init timed out"}

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
                        return {"success": False, "error": f"Check-Host result failed: HTTP {response.status}"}

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
                        # All nodes returned empty results - domain doesn't resolve
                        return {"success": False, "error": "Domain does not resolve on Check-Host nodes"}

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

        return {"success": False, "error": "Check-Host result polling timed out"}


def _is_ip_address(host: str) -> bool:
    """Check if a string is an IPv4 or IPv6 address."""
    try:
        ip_address(host)
        return True
    except ValueError:
        return False
