"""RKN throttle check — detects 16-20KB connection throttling by DPI filters.

This check detects a specific type of blocking used by Russian DPI (Deep Packet Inspection)
systems. The connection is technically established, but data transfer is abruptly terminated
after the first 16-20 KB (typically 10-14 packets). This is enough for the browser to start
rendering, but critical resources (JS bundles, styles, API calls) fail to load.

The check works by:
1. Making an HTTP request to the target host through the proxy (or directly)
2. Downloading a large response (default: 100KB range request)
3. Checking if the connection was throttled (received only 16-20KB before timeout/disconnect)
4. If throttled, the host is likely subject to RKN DPI filtering

References:
- https://github.com/bol-van/zapret
- RKN DPI filtering behavior analysis
"""

import asyncio

import aiohttp

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("rkn_throttle_checker")

# Thresholds for detecting RKN throttle
RKN_THROTTLE_MIN_BYTES = 14_000  # ~14KB minimum
RKN_THROTTLE_MAX_BYTES = 22_000  # ~22KB maximum
RKN_THROTTLE_TEST_SIZE = 65_536  # 64KB range request
RKN_THROTTLE_TIMEOUT = 8  # seconds timeout for throttle test


async def check_rkn_throttle_direct(
    host: str,
    port: int = 443,
    path: str = "/",
) -> DiagnosticResult:
    """
    Check if a host is subject to RKN DPI throttling (direct connection).

    Makes a range request to detect if the connection is throttled after 16-20KB.

    Args:
        host: Target host (domain or IP)
        port: Target port (default 443)
        path: URL path to request (default: "/")
    """
    url = f"https://{host}:{port}{path}"
    log.debug("Checking RKN throttle (direct)", host=host, port=port, path=path)

    return await _perform_throttle_check(url, host, proxy_url=None, label_suffix="")


async def check_rkn_throttle_via_proxy(
    proxy_url: str,
    sni_domain: str,
) -> DiagnosticResult:
    """
    Check if a host is subject to RKN DPI throttling through a proxy.

    This is useful for checking the SNI domain from a problematic host
    to see if it's being throttled when accessed through the proxy.

    Args:
        proxy_url: Proxy URL (http/socks5)
        sni_domain: SNI domain to test (from the problematic host config)
    """
    url = f"https://{sni_domain}/"
    log.debug("Checking RKN throttle (via proxy)", proxy_url=proxy_url, sni_domain=sni_domain)

    label_suffix = f" (через прокси: {proxy_url})"
    return await _perform_throttle_check(url, sni_domain, proxy_url=proxy_url, label_suffix=label_suffix)


async def check_rkn_throttle_via_xray(
    socks_url: str,
    sni_domain: str,
    share_name: str = "",
    label_suffix: str = "",
) -> DiagnosticResult:
    """
    Check if a host is subject to RKN DPI throttling through Xray SOCKS tunnel.

    Args:
        socks_url: Local SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)
        sni_domain: SNI domain to test
        share_name: Proxy name for display
        share_protocol: Protocol name for display
        label_suffix: Additional label suffix for check name
    """
    url = f"https://{sni_domain}/"
    log.debug("Checking RKN throttle (via Xray)", sni_domain=sni_domain)

    full_label = f" (Xray: {share_name})" if share_name else label_suffix
    return await _perform_throttle_check(url, sni_domain, proxy_url=socks_url, label_suffix=full_label)


async def _perform_throttle_check(
    url: str,
    target: str,
    proxy_url: str | None = None,
    label_suffix: str = "",
) -> DiagnosticResult:
    """
    Perform the actual throttle detection check.

    Makes a range request for 64KB and checks if we receive only 16-20KB
    before the connection is throttled/times out.
    """
    start_time = asyncio.get_running_loop().time()
    check_name = f"RKN Throttle{label_suffix}"

    try:
        async with aiohttp.ClientSession() as session:
            # Make a range request for 64KB — enough to detect 16-20KB throttle
            headers = {"Range": f"bytes=0-{RKN_THROTTLE_TEST_SIZE - 1}"}

            timeout = aiohttp.ClientTimeout(
                total=RKN_THROTTLE_TIMEOUT,
                connect=5,
                sock_read=5,
            )

            async with session.get(
                url,
                proxy=proxy_url,
                timeout=timeout,
                headers=headers,
                allow_redirects=True,
                ssl=False,  # We're checking throttling, not TLS validity
            ) as response:
                # Read the response body in chunks to detect throttling
                total_bytes = 0
                chunk_count = 0
                timed_out = False

                try:
                    async for chunk in response.content.iter_chunked(4096):
                        total_bytes += len(chunk)
                        chunk_count += 1

                        # Safety limit — if we get more than throttle threshold, it's not throttled
                        if total_bytes > RKN_THROTTLE_MAX_BYTES:
                            break

                except TimeoutError:
                    timed_out = True
                    log.debug(
                        "Throttle check timeout",
                        target=target,
                        total_bytes=total_bytes,
                        chunks=chunk_count,
                    )
                except (
                    aiohttp.ClientConnectionError,
                    aiohttp.ServerDisconnectedError,
                    ConnectionResetError,
                    OSError,
                ) as e:
                    # Connection was reset — typical for DPI throttle
                    log.debug(
                        "Throttle check connection reset",
                        target=target,
                        total_bytes=total_bytes,
                        chunks=chunk_count,
                        error=str(e),
                    )

                duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000

                details = {
                    "target": target,
                    "url": url,
                    "total_bytes_received": total_bytes,
                    "chunk_count": chunk_count,
                    "http_status": response.status,
                    "duration_ms": round(duration_ms, 2),
                    "proxy": proxy_url or "direct",
                }

                # CASE 1: Timeout with 0 bytes → IP is fully blocked (not throttle)
                if total_bytes == 0 and timed_out:
                    log.info(
                        "RKN check: IP fully blocked (0 bytes, timeout)",
                        target=target,
                    )

                    return DiagnosticResult(
                        check_name=check_name,
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.CRITICAL,
                        message=(
                            f"IP полностью заблокирован: соединение зависло, 0 байт получено "
                            f"за {RKN_THROTTLE_TIMEOUT}s — сервер не отвечает"
                        ),
                        details=details,
                        recommendations=[
                            "IP-адрес сервера заблокирован РКН — соединение не устанавливается",
                            "Смените IP-адрес сервера на новый из другой подсети",
                            "Или прокиньте мост через рабочий прокси до этого сервера",
                        ],
                    )

                # CASE 2: 14-22KB received → DPI throttle pattern
                is_throttled = RKN_THROTTLE_MIN_BYTES <= total_bytes <= RKN_THROTTLE_MAX_BYTES and (
                    timed_out or response.status != 206
                )

                if is_throttled:
                    log.warning(
                        "RKN throttle detected",
                        target=target,
                        bytes_received=total_bytes,
                        duration_ms=round(duration_ms, 2),
                    )

                    return DiagnosticResult(
                        check_name=check_name,
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.CRITICAL,
                        message=(
                            f"Обнаружена RKN-блокировка (DPI throttle): "
                            f"получено {total_bytes} байт ({total_bytes / 1024:.1f}KB) вместо ожидаемых данных. "
                            f"Соединение разорвано после ~{total_bytes / 1024:.0f}KB — типичный паттерн DPI."
                        ),
                        details=details,
                        recommendations=[
                            "Сервер подвержен блокировке через DPI-фильтры РКН",
                            "Соединение обрывается после 16-20KB — характерный признак 'удушения'",
                            "Попробуйте использовать обфускацию или альтернативные протоколы",
                            "VLESS + Reality + XHTTP/GRPC могут помочь обойти блокировку",
                        ],
                    )
                elif total_bytes > RKN_THROTTLE_MAX_BYTES:
                    # Got more than throttle threshold — connection is working
                    log.info(
                        "RKN throttle check passed",
                        target=target,
                        bytes_received=total_bytes,
                        duration_ms=round(duration_ms, 2),
                    )

                    return DiagnosticResult(
                        check_name=check_name,
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message=f"RKN DPI throttle не обнаружено: получено {total_bytes} байт",
                        details=details,
                    )
                else:
                    # Got less than minimum — small response or other issue
                    log.debug(
                        "RKN throttle check inconclusive",
                        target=target,
                        bytes_received=total_bytes,
                        http_status=response.status,
                    )

                    return DiagnosticResult(
                        check_name=check_name,
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.INFO,
                        message=(
                            f"RKN DPI throttle не обнаружено: получено {total_bytes} байт (HTTP {response.status})"
                        ),
                        details=details,
                    )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("RKN throttle check timeout", target=target)

        return DiagnosticResult(
            check_name=check_name,
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=(
                f"IP полностью заблокирован: не удалось установить соединение "
                f"за {RKN_THROTTLE_TIMEOUT}s — сервер не отвечает"
            ),
            details={
                "target": target,
                "timeout_seconds": RKN_THROTTLE_TIMEOUT,
                "duration_ms": round(duration_ms, 2),
                "bytes_received": 0,
            },
            recommendations=[
                "IP-адрес сервера заблокирован РКН — соединение не устанавливается",
                "Смените IP-адрес сервера на новый из другой подсети",
                "Или прокиньте мост через рабочий прокси до этого сервера",
            ],
        )

    except aiohttp.ClientConnectionError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("RKN throttle connection error", target=target, error=str(e))

        return DiagnosticResult(
            check_name=check_name,
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Ошибка подключения при проверке RKN throttle: {e}",
            details={
                "target": target,
                "error": str(e),
                "error_type": "ClientConnectionError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Не удалось подключиться к серверу",
                "Проверьте доступность хоста",
            ],
        )

    except aiohttp.ClientError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("RKN throttle client error", target=target, error=str(e))

        return DiagnosticResult(
            check_name=check_name,
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Ошибка при проверке RKN throttle: {e}",
            details={
                "target": target,
                "error": str(e),
                "error_type": type(e).__name__,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Произошла ошибка при проверке — проверьте логи",
                "Попробуйте повторить попытку",
            ],
        )

    except Exception as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("RKN throttle unexpected error", target=target, error=str(e))

        return DiagnosticResult(
            check_name=check_name,
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Неожиданная ошибка при проверке RKN throttle: {e}",
            details={
                "target": target,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Произошла неожиданная ошибка — проверьте логи",
                "Попробуйте повторить попытку",
            ],
        )
