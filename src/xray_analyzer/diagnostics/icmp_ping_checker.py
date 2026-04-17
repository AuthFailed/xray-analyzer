"""ICMP ping diagnostic check via system `ping` command."""

import asyncio
import re

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("icmp_ping_checker")

# Pattern for the summary line: rtt min/avg/max/mdev = 1.234/5.678/9.012/0.345 ms
_RTT_RE = re.compile(
    r"rtt min/avg/max/mdev\s*=\s*"
    r"(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)\s*ms"
)
# Pattern for packet loss: 3 packets transmitted, 2 received, 33% packet loss
_LOSS_RE = re.compile(
    r"(?P<tx>\d+)\s+packets?\s+transmitted.*?"
    r"(?P<rx>\d+)\s+received.*?"
    r"(?P<loss>[\d.]+)%\s+packet\s+loss"
)


async def check_icmp_ping(host: str, count: int = 3) -> DiagnosticResult:
    """
    ICMP ping check — runs system ``ping`` and parses output.

    Uses ``ping -c <count> -W <timeout> <host>`` which works without root
    on Linux (setuid binary).
    """
    timeout = settings.icmp_ping_timeout
    start_time = asyncio.get_running_loop().time()
    log.debug("Checking ICMP ping", host=host, count=count, timeout=timeout)

    try:
        proc = await asyncio.wait_for(
            _run_ping(host, count, timeout),
            timeout=count * timeout + 3,
        )
    except FileNotFoundError:
        return DiagnosticResult(
            check_name="ICMP Ping",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.INFO,
            message="ping binary not found",
            details={"host": host},
        )
    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        return DiagnosticResult(
            check_name="ICMP Ping",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.WARNING,
            message=f"ICMP ping to {host}: timed out",
            details={"host": host, "duration_ms": round(duration_ms, 2)},
        )

    duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
    stdout = proc.stdout or ""

    # Parse results
    tx, rx, loss_pct = _parse_loss(stdout)
    rtt_min, rtt_avg, rtt_max = _parse_rtt(stdout)

    details: dict = {
        "host": host,
        "attempts": tx or count,
        "successful": rx or 0,
        "failed": (tx or count) - (rx or 0),
        "packet_loss_pct": loss_pct if loss_pct is not None else 100.0,
        "duration_ms": round(duration_ms, 2),
    }

    if rtt_avg is not None:
        details["latency_min_ms"] = rtt_min
        details["latency_avg_ms"] = rtt_avg
        details["latency_max_ms"] = rtt_max

    # Determine status
    if rx is not None and rx == (tx or count):
        # All replies received
        severity = CheckSeverity.INFO
        if rtt_avg and rtt_avg > 1000:
            severity = CheckSeverity.ERROR
        elif rtt_avg and rtt_avg > 500:
            severity = CheckSeverity.WARNING

        return DiagnosticResult(
            check_name="ICMP Ping",
            status=CheckStatus.PASS,
            severity=severity,
            message=(
                f"ICMP ping to {host}: avg={details.get('latency_avg_ms', '?')}ms, "
                f"min={details.get('latency_min_ms', '?')}ms, "
                f"max={details.get('latency_max_ms', '?')}ms"
            ),
            details=details,
        )

    if rx and rx > 0:
        # Partial loss
        return DiagnosticResult(
            check_name="ICMP Ping",
            status=CheckStatus.WARN,
            severity=CheckSeverity.INFO,
            message=(
                f"ICMP ping to {host}: {details['packet_loss_pct']:.0f}% loss, "
                f"avg={details.get('latency_avg_ms', '?')}ms"
            ),
            details=details,
        )

    # All lost
    return DiagnosticResult(
        check_name="ICMP Ping",
        status=CheckStatus.FAIL,
        severity=CheckSeverity.WARNING,
        message=f"ICMP ping to {host}: all {tx or count} packets lost",
        details=details,
    )


async def _run_ping(host: str, count: int, timeout: int) -> asyncio.subprocess.Process:
    """Run the system ping command and return the completed process."""
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", str(count), "-W", str(timeout), host,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await proc.communicate()
    # Attach decoded output to the process object for convenience
    proc.stdout = stdout_bytes.decode(errors="replace")  # type: ignore[assignment]
    proc.stderr = stderr_bytes.decode(errors="replace")  # type: ignore[assignment]
    return proc


def _parse_rtt(output: str) -> tuple[float | None, float | None, float | None]:
    """Extract min/avg/max from ping summary line."""
    m = _RTT_RE.search(output)
    if not m:
        return None, None, None
    return (
        round(float(m.group("min")), 2),
        round(float(m.group("avg")), 2),
        round(float(m.group("max")), 2),
    )


def _parse_loss(output: str) -> tuple[int | None, int | None, float | None]:
    """Extract transmitted/received/loss% from ping output."""
    m = _LOSS_RE.search(output)
    if not m:
        return None, None, None
    return int(m.group("tx")), int(m.group("rx")), float(m.group("loss"))
