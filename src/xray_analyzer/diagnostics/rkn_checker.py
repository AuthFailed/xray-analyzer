"""RKN (Roskomnadzor) domain and IP blocking check."""

import asyncio
import ipaddress
from typing import Any
from urllib.parse import urlparse

import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("rkn_checker")


async def check_rkn_blocking(domain: str) -> DiagnosticResult:
    """
    Check if a domain or IP is blocked by Roskomnadzor using rknweb.ru API.

    Supports both domain names and IP addresses.
    For IPs, uses the /v3/ips/ endpoint; for domains, uses /v3/domains/.

    Returns warning if domain/IP is in the blocking list.
    """
    if not settings.rkn_check_enabled:
        return DiagnosticResult(
            check_name="RKN Block Check",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.INFO,
            message="RKN block check is disabled in configuration",
        )

    # Determine if input is an IP or domain
    is_ip = _is_ip_address(domain)

    start_time = asyncio.get_event_loop().time()
    log.debug("Checking RKN blocking", domain=domain, is_ip=is_ip)

    try:
        async with aiohttp.ClientSession() as session:
            base_url = settings.rkn_api_url.rstrip("/")

            # Choose endpoint based on input type
            if is_ip:
                api_url = f"{base_url}/v3/ips/" if base_url.endswith("/api") else f"{base_url}/api/v3/ips/"
                params = {"ip": domain}
                check_type = "IP"
            else:
                api_url = f"{base_url}/v3/domains/" if base_url.endswith("/api") else f"{base_url}/api/v3/domains/"
                params = {"domain": domain}
                check_type = "Domain"

            async with session.get(
                api_url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
                content_type = response.content_type or ""

                # Check if response is actually JSON
                if "json" not in content_type:
                    log.debug(
                        "RKN API returned non-JSON response",
                        domain=domain,
                        status=response.status,
                    )
                    return DiagnosticResult(
                        check_name="RKN Block Check",
                        status=CheckStatus.SKIP,
                        severity=CheckSeverity.INFO,
                        message=f"RKN API недоступен — проверка {check_type} пропущена",
                        details={check_type.lower(): domain},
                    )

                data = await response.json()

                log.info(
                    "RKN check completed",
                    domain=domain,
                    status_code=response.status,
                    response=data,
                )

                # Parse response to determine blocking status
                is_blocked = _parse_rkn_response(data)

                if is_blocked:
                    return DiagnosticResult(
                        check_name="RKN Block Check",
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.CRITICAL,
                        message=f"{check_type} {domain} заблокирован Роскомнадзором",
                        details={
                            check_type.lower(): domain,
                            "is_blocked": True,
                            "rkn_response": data,
                            "duration_ms": round(duration_ms, 2),
                        },
                        recommendations=[
                            f"{check_type} {domain} находится в реестре заблокированных",
                            "Используйте другой домен/IP или зеркало сервера",
                            "Рассмотрите использование VPN или прокси для обхода блокировки",
                            "Проверьте актуальный статус блокировки в реестре rkn.gov.ru",
                        ],
                    )
                else:
                    return DiagnosticResult(
                        check_name="RKN Block Check",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message=f"{check_type} {domain} не заблокирован Роскомнадзором",
                        details={
                            check_type.lower(): domain,
                            "is_blocked": False,
                            "rkn_response": data,
                            "duration_ms": round(duration_ms, 2),
                        },
                    )

    except TimeoutError:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("RKN check timed out", domain=domain)

        return DiagnosticResult(
            check_name="RKN Block Check",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.WARNING,
            message=f"Превышено время ожидания ответа от RKN API для {domain}",
            details={
                "domain": domain,
                "timeout_seconds": 10,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "RKN API недоступен — повторите проверку позже",
                "Проверьте вручную через https://reestr.rublacklist.net/",
            ],
        )

    except aiohttp.ClientResponseError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("RKN check HTTP error", domain=domain, status=e.status, error=str(e))

        return DiagnosticResult(
            check_name="RKN Block Check",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.INFO,
            message=f"RKN API недоступен (HTTP {e.status}) — проверка пропущена",
            details={
                "domain": domain,
                "http_status": e.status,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "RKN API вернул ошибку — проверьте конфигурацию",
                "Проверьте вручную через https://reestr.rublacklist.net/",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("RKN check HTTP error", domain=domain, error=str(e))

        return DiagnosticResult(
            check_name="RKN Block Check",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.WARNING,
            message=f"Ошибка при проверке RKN для {domain}: {e}",
            details={
                "domain": domain,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Не удалось проверить статус блокировки через API",
                "Проверьте вручную через https://reestr.rublacklist.net/",
                "Проверьте доступность RKN API: curl https://rknweb.ru/api/check?domain=<домен>",
            ],
        )

    except Exception as e:
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.error("RKN check unexpected error", domain=domain, error=str(e))

        return DiagnosticResult(
            check_name="RKN Block Check",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.WARNING,
            message=f"Неожиданная ошибка при проверке RKN для {domain}: {e}",
            details={
                "domain": domain,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Произошла ошибка — проверьте статус блокировки вручную",
                "Используйте: https://reestr.rublacklist.net/",
            ],
        )


def _is_ip_address(value: str) -> bool:
    """Check if a string is an IP address (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_rkn_response(data: dict[str, Any]) -> bool:
    """
    Parse RKN API response to determine if domain is blocked.

    Expected response formats:
    - {"0":"element","1":"element"} — domain is blocked (has entries)
    - {} — domain is not blocked (empty)
    - {"blocked": true, ...} — direct boolean
    - {"error": ..., "message": ...} — error response
    """
    # Error response
    if "error" in data:
        log.warning("RKN API returned error", error=data.get("error"), message=data.get("message"))
        return False

    # Numeric keys indicate blocked entries
    if any(str(k).isdigit() for k in data):
        return len(data) > 0

    # Status string field
    if "status" in data:
        status = str(data["status"]).lower()
        return status in ("blocked", "restricted", "banned")

    # Nested result object
    if "result" in data and isinstance(data["result"], dict):
        if "blocked" in data["result"]:
            return bool(data["result"]["blocked"])
        if "status" in data["result"]:
            return str(data["result"]["status"]).lower() in (
                "blocked",
                "restricted",
                "banned",
            )

    # Check for common positive blocking indicators
    for key in ("is_blocked", "blacklisted", "restricted"):
        if key in data:
            return bool(data[key])

    # If response indicates success but no blocking info, assume not blocked
    if data.get("success") is True and not any(k in data for k in ("blocked", "status", "result")):
        return False

    # Default: if we can't determine, assume not blocked (conservative approach)
    # Log warning about ambiguous response
    log.warning("Ambiguous RKN API response, assuming not blocked", response=data)
    return False


def extract_domain_from_url(url: str) -> str:
    """Extract domain from a URL string."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url
