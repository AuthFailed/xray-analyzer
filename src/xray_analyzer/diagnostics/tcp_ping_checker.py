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

    # Small delay between attempts — back-to-back SYNs can trigger rate limits /
    # SYN-cookie behavior on some servers, producing false "packet loss" when
    # TCP Connection itself works.
    inter_attempt_delay = 0.1

    for i in range(count):
        if i > 0:
            await asyncio.sleep(inter_attempt_delay)

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
        # All successful — but if any single attempt landed within 90% of the
        # timeout it didn't *really* succeed, just barely scraped through. Demote
        # such cases to WARN so the report doesn't claim everything is fine.
        timeout_ms = settings.tcp_timeout * 1000
        max_latency = max(latencies)
        avg_latency = sum(latencies) / len(latencies)

        if max_latency >= 0.9 * timeout_ms:
            return DiagnosticResult(
                check_name="TCP Ping",
                status=CheckStatus.WARN,
                severity=CheckSeverity.INFO,
                message=(
                    f"TCP ping {host}:{port} very slow: avg={details['latency_avg_ms']}ms, "
                    f"max={details['latency_max_ms']}ms (close to {settings.tcp_timeout}s timeout)"
                ),
                details=details,
            )

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
        # Partial success — likely rate limiting; surface as WARN (not FAIL) so it
        # doesn't override the authoritative TCP Connection result.
        return DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.WARN,
            severity=CheckSeverity.INFO,
            message=(
                f"Unstable response from {host}:{port}: {packet_loss_pct:.0f}% loss, "
                f"avg={details.get('latency_avg_ms', 'N/A')}ms (likely SYN-retry rate-limiting)"
            ),
            details=details,
        )
    else:
        # All failed — keep as FAIL but WARNING severity (not CRITICAL). The authoritative
        # signal is TCP Connection; TCP Ping alone shouldn't push overall status to FAIL
        # when servers throttle back-to-back TCP handshakes.
        return DiagnosticResult(
            check_name="TCP Ping",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.WARNING,
            message=f"TCP ping to {host}:{port}: all {count} attempts failed",
            details=details,
            recommendations=[
                f"Server {host}:{port} not responding to repeat TCP probes",
                "If TCP Connection passed — likely SYN-flood protection on the server",
                "Otherwise check firewall and port accessibility",
            ],
        )
