"""DNS diagnostic checks."""

import asyncio
import socket
from ipaddress import ip_address

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("dns_checker")


async def check_dns_resolution(host: str) -> DiagnosticResult:
    """
    Check if a host can be resolved via DNS.

    Returns a DiagnosticResult with status, resolved IPs, and recommendations.
    """
    start_time = asyncio.get_event_loop().time()
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

        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000

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
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        error_msg = str(e)

        log.error("DNS resolution failed", host=host, error=error_msg)

        severity = CheckSeverity.CRITICAL
        _get_dns_recommendation(error_msg)

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
        )

    except TimeoutError:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
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
