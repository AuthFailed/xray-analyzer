"""TCP ping diagnostic check."""

import asyncio

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("tcp_ping_checker")


async def check_tcp_ping(host: str, port: int = 443, count: int = 3) -> DiagnosticResult:
    """
    TCP ping check - measures connection latency to host:port.

    Performs multiple connection attempts and calculates statistics
    (min, max, avg latency, packet loss).

    Args:
        host: Target hostname or IP address
        port: Target port (default: 443)
        count: Number of connection attempts (default: 3)
    """
    start_time = asyncio.get_running_loop().time()
    log.debug("Checking TCP ping", host=host, port=port, count=count)

    latencies: list[float] = []
    failures = 0
    errors: list[str] = []

    for i in range(count):
        attempt_start = asyncio.get_running_loop().time()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=settings.tcp_timeout,
            )
            writer.close()
            await writer.wait_closed()

            attempt_ms = (asyncio.get_running_loop().time() - attempt_start) * 1000
            latencies.append(attempt_ms)
            log.debug(f"TCP ping attempt {i + 1}/{count}", host=host, port=port, latency_ms=round(attempt_ms, 2))

        except TimeoutError:
            failures += 1
            errors.append(f"Attempt {i + 1}: timeout")
            log.debug(f"TCP ping attempt {i + 1}/{count} timed out", host=host, port=port)
        except (ConnectionRefusedError, OSError) as e:
            failures += 1
            errors.append(f"Attempt {i + 1}: {e}")
            log.debug(f"TCP ping attempt {i + 1}/{count} failed", host=host, port=port, error=str(e))

    total_duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
    packet_loss_pct = (failures / count * 100) if count > 0 else 100

    details = {
        "host": host,
        "port": port,
        "attempts": count,
        "successful": len(latencies),
        "failed": failures,
        "packet_loss_pct": round(packet_loss_pct, 1),
        "duration_ms": round(total_duration_ms, 2),
        "timeout_seconds": settings.tcp_timeout,
    }

    if latencies:
        details.update(
            {
                "latency_min_ms": round(min(latencies), 2),
                "latency_max_ms": round(max(latencies), 2),
                "latency_avg_ms": round(sum(latencies) / len(latencies), 2),
                "latencies_ms": [round(lat, 2) for lat in latencies],
            }
        )

    if errors:
        details["errors"] = errors

    # Determine status
    if len(latencies) == count:
        # All successful
        avg_latency = sum(latencies) / len(latencies)
        severity = CheckSeverity.INFO
        if avg_latency > 1000:
            severity = CheckSeverity.ERROR
        elif avg_latency > 500:
            severity = CheckSeverity.WARNING

        return DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.PASS,
            severity=severity,
            message=(
                f"TCP ping to {host}:{port}: avg={details['latency_avg_ms']}ms, "
                f"min={details['latency_min_ms']}ms, max={details['latency_max_ms']}ms"
            ),
            details=details,
        )
    elif len(latencies) > 0:
        # Partial success
        return DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.WARNING,
            message=(
                f"TCP ping to {host}:{port}: packet loss {packet_loss_pct:.0f}%, "
                f"avg={details.get('latency_avg_ms', 'N/A')}ms"
            ),
            details=details,
            recommendations=[
                f"Частичная потеря пакетей ({packet_loss_pct:.0f}%) до {host}:{port}",
                "Проверьте стабильность сетевого подключения",
                "Возможна перегрузка сети или сервера",
            ],
        )
    else:
        # All failed
        return DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.CRITICAL,
            message=f"TCP ping to {host}:{port}: все {count} попыток неудачны",
            details=details,
            recommendations=[
                f"Сервер {host}:{port} недоступен — все {count} попыток подключения неудачны",
                "Проверьте настройки фаервола (iptables, ufw)",
                f"Убедитесь, что порт {port} открыт: netstat -tlnp | grep {port}",
                "Проверьте сетевую доступность: ping <хост>",
            ],
        )
