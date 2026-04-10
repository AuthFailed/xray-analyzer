"""DNS diagnostic checks."""

import asyncio
import socket
from ipaddress import ip_address
from typing import Any

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("dns_checker")

CHECK_HOST_BASE_URL = "https://check-host.net"


async def check_dns_resolution(host: str) -> DiagnosticResult:
    """
    Check if a host can be resolved via DNS.

    Returns a DiagnosticResult with status, resolved IPs, and recommendations.
    """
    start_time = asyncio.get_running_loop().time()
    log.debug("Checking DNS resolution", host=host)

    try:
        loop = asyncio.get_event_loop()
        addr_infos = await loop.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

        # Collect unique IP addresses
        resolved_ips: list[str] = []
        for _family, _, _, _, sockaddr in addr_infos:
            ip = sockaddr[0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000

        ip_types = []
        for ip_str in resolved_ips:
            try:
                ip_types.append("IPv6" if ip_address(ip_str).version == 6 else "IPv4")
            except ValueError:
                ip_types.append("unknown")

        log.info(
            "DNS resolution successful",
            host=host,
            ips=resolved_ips,
            duration_ms=round(duration_ms, 2),
        )

        return DiagnosticResult(
            check_name="DNS Resolution",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=f"DNS resolved successfully for {host}",
            details={
                "resolved_ips": resolved_ips,
                "ip_types": ip_types,
                "address_count": len(resolved_ips),
                "duration_ms": round(duration_ms, 2),
            },
        )

    except socket.gaierror as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        error_msg = str(e)

        log.error("DNS resolution failed", host=host, error=error_msg)

        severity = CheckSeverity.CRITICAL
        recommendations = _get_dns_recommendation(error_msg)

        return DiagnosticResult(
            check_name="DNS Resolution",
            status=CheckStatus.FAIL,
            severity=severity,
            message=f"DNS resolution failed for {host}: {error_msg}",
            details={
                "error_code": e.errno,
                "error_str": error_msg,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=recommendations,
        )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
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
                "Проверьте настройки DNS-сервера в /etc/resolv.conf",
                "Убедитесь, что DNS-сервер доступен",
                "Попробуйте использовать публичные DNS (8.8.8.8, 1.1.1.1)",
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
    start_time = asyncio.get_running_loop().time()
    log.debug("Checking DNS resolution with Check-Host.net comparison", host=host)

    # Run local DNS and Check-Host concurrently
    local_task = asyncio.create_task(_local_dns_resolve(host))
    checkhost_task = asyncio.create_task(_checkhost_dns_resolve(host))

    local_result = await local_task
    checkhost_result = await checkhost_task

    duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000

    # Build details
    details: dict[str, Any] = {
        "host": host,
        "local_ips": local_result.get("ips", []),
        "checkhost_ips": checkhost_result.get("ips", []),
        "duration_ms": round(duration_ms, 2),
    }

    local_success = local_result.get("success", False)
    checkhost_success = checkhost_result.get("success", False)

    # If Check-Host failed, report based on local result only
    if not checkhost_success:
        checkhost_error = checkhost_result.get("error", "Check-Host API error")
        details["checkhost_error"] = checkhost_error

        if local_success:
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.PASS,
                severity=CheckSeverity.INFO,
                message=f"DNS resolved successfully for {host} (Check-Host недоступен)",
                details=details,
            )
        else:
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                message=f"DNS resolution failed for {host}: {local_result.get('error', 'unknown')}",
                details=details,
            )

    # Compare IPs
    local_ips = set(local_result.get("ips", []))
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
            return DiagnosticResult(
                check_name="DNS Resolution (Check-Host)",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.WARNING,
                message=(
                    f"DNS для {host}: локальные IP не совпадают с Check-Host (возможно DNS poisoning или geo-blocking)"
                ),
                details=details,
                recommendations=[
                    "Локальный DNS возвращает IP, отличные от Check-Host.net",
                    "Возможна DNS-подмена или geo-блокировка",
                    "Проверьте: dig @8.8.8.8 <домен> и сравните с dig <домен>",
                    "Попробуйте использовать публичные DNS (8.8.8.8, 1.1.1.1)",
                ],
            )
    elif not local_success and checkhost_success:
        # Local DNS fails but Check-Host resolves - DNS issue
        return DiagnosticResult(
            check_name="DNS Resolution (Check-Host)",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"Локальный DNS не разрешает {host}, но Check-Host разрешает (проблема DNS)",
            details=details,
            recommendations=[
                "Check-Host.net успешно разрешает домен, но локальный DNS — нет",
                "Проверьте настройки DNS-сервера в /etc/resolv.conf",
                "Попробуйте использовать публичные DNS (8.8.8.8, 1.1.1.1)",
            ],
        )
    else:
        # Both fail
        return DiagnosticResult(
            check_name="DNS Resolution (Check-Host)",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"DNS не разрешает {host} ни локально, ни через Check-Host",
            details=details,
            recommendations=[
                "Домен не разрешается ни локально, ни через Check-Host.net",
                "Проверьте правильность написания доменного имени",
                "Убедитесь, что домен зарегистрирован и активен",
            ],
        )


async def _local_dns_resolve(host: str) -> dict[str, Any]:
    """Resolve host using local DNS."""
    try:
        loop = asyncio.get_event_loop()
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
                        # The result is a list with a single dict inside
                        if isinstance(node_result, list) and len(node_result) > 0:
                            dns_data = node_result[0]
                            if isinstance(dns_data, dict):
                                a_records = dns_data.get("A", [])
                                aaaa_records = dns_data.get("AAAA", [])
                                all_ips.extend(a_records)
                                all_ips.extend(aaaa_records)

                    if all_done and all_ips:
                        # Deduplicate preserving order
                        seen = set()
                        unique_ips = []
                        for ip in all_ips:
                            if ip not in seen:
                                seen.add(ip)
                                unique_ips.append(ip)
                        return {"success": True, "ips": unique_ips}

                    if not has_pending and not all_ips:
                        # All nodes returned empty results - domain doesn't resolve
                        return {"success": False, "error": "Domain does not resolve on Check-Host nodes"}

                    # Still polling if some nodes are pending but we have at least one result
                    if all_ips:
                        seen = set()
                        unique_ips = []
                        for ip in all_ips:
                            if ip not in seen:
                                seen.add(ip)
                                unique_ips.append(ip)
                        return {"success": True, "ips": unique_ips}

            except aiohttp.ClientError, TimeoutError:
                continue

        return {"success": False, "error": "Check-Host result polling timed out"}


def _get_dns_recommendation(error_msg: str) -> list[str]:
    """Get recommendations based on the DNS error type."""
    recommendations = []

    error_lower = error_msg.lower()

    if "nodename" in error_lower or "name" in error_lower:
        recommendations.extend(
            [
                "Проверьте правильность написания доменного имени",
                "Убедитесь, что домен зарегистрирован и активен",
                "Проверьте настройки DNS-сервера (/etc/resolv.conf)",
                "Попробуйте: dig <домен> или nslookup <домен>",
            ]
        )
    elif "servfail" in error_lower:
        recommendations.extend(
            [
                "DNS-сервер вернул ошибку SERFAIL — проблема на стороне DNS-сервера",
                "Попробуйте использовать другой DNS-сервер",
                "Проверьте: dig @8.8.8.8 <домен>",
            ]
        )
    else:
        recommendations.extend(
            [
                "Проверьте настройки DNS-сервера",
                "Убедитесь, что сетевое подключение активно",
                "Попробуйте: ping <домен> для проверки доступности",
            ]
        )

    return recommendations
