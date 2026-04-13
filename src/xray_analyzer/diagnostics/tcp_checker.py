"""TCP connection diagnostic checks with timeout and error handling."""

import asyncio

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult

log = get_logger("tcp_checker")


async def check_tcp_connection(host: str, port: int) -> DiagnosticResult:
    """
    Check TCP connection to host:port with timeout handling.

    Detects:
    - Connection timeouts
    - Connection refused
    - Network unreachable
    - Other connection errors
    """
    start_time = asyncio.get_running_loop().time()
    log.debug("Checking TCP connection", host=host, port=port)

    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=settings.tcp_timeout,
        )
        writer.close()
        await writer.wait_closed()

        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000

        log.info(
            "TCP connection successful",
            host=host,
            port=port,
            duration_ms=round(duration_ms, 2),
        )

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.PASS,
            severity=CheckSeverity.INFO,
            message=f"TCP connection to {host}:{port} established successfully",
            details={
                "host": host,
                "port": port,
                "duration_ms": round(duration_ms, 2),
                "timeout_seconds": settings.tcp_timeout,
            },
        )

    except TimeoutError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error(
            "TCP connection timed out",
            host=host,
            port=port,
            timeout=settings.tcp_timeout,
        )

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.TIMEOUT,
            severity=CheckSeverity.CRITICAL,
            message=f"TCP connection to {host}:{port} timed out ({settings.tcp_timeout}s)",
            details={
                "host": host,
                "port": port,
                "timeout_seconds": settings.tcp_timeout,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "Server not responding — check if the service is running on this port",
                "Check firewall settings (iptables, ufw)",
                "Verify port is open on server: netstat -tlnp | grep <port>",
                "Check network reachability: ping <host>",
                "Server may be overloaded or there are network issues",
            ],
        )

    except ConnectionRefusedError:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("TCP connection refused", host=host, port=port)

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Connection refused by {host}:{port}",
            details={
                "host": host,
                "port": port,
                "error": "ConnectionRefusedError",
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                f"Port {port} is closed on server {host}",
                "Check if the service is running: systemctl status <service>",
                "Check firewall rules on the server",
                "Make sure the service is listening on the correct port",
                "Try: telnet <host> <port> or nc -zv <host> <port>",
            ],
        )

    except OSError as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        error_str = str(e)
        log.error("TCP connection OS error", host=host, port=port, error=error_str)

        severity, message, recommendations = _handle_os_error(e, host, port)

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.FAIL,
            severity=severity,
            message=message,
            details={
                "host": host,
                "port": port,
                "error_code": e.errno,
                "error_str": error_str,
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=recommendations,
        )

    except Exception as e:
        duration_ms = (asyncio.get_running_loop().time() - start_time) * 1000
        log.error("TCP connection unexpected error", host=host, port=port, error=str(e))

        return DiagnosticResult(
            check_name="TCP Connection",
            status=CheckStatus.FAIL,
            severity=CheckSeverity.ERROR,
            message=f"Unexpected error connecting to {host}:{port}: {e}",
            details={
                "host": host,
                "port": port,
                "error_type": type(e).__name__,
                "error_str": str(e),
                "duration_ms": round(duration_ms, 2),
            },
            recommendations=[
                "An unexpected error occurred — check system logs",
                "Try again",
            ],
        )


def _handle_os_error(e: OSError, host: str, port: int) -> tuple[CheckSeverity, str, list[str]]:
    """Handle specific OSError codes and return severity, message, recommendations."""
    error_code = e.errno

    if error_code == 101:  # Network is unreachable
        return (
            CheckSeverity.CRITICAL,
            f"Network unreachable when connecting to {host}:{port}",
            [
                "Check network connectivity",
                "Verify routing table: ip route",
                "Check network interface settings",
                "Try: ping 8.8.8.8 to verify internet access",
            ],
        )
    elif error_code == 110:  # Connection timed out
        return (
            CheckSeverity.CRITICAL,
            f"Connection timed out to {host}:{port}",
            [
                "Server not responding within the timeout period",
                "Check firewall settings",
                "Verify server is reachable",
            ],
        )
    elif error_code == 111:  # Connection refused (already handled, but fallback)
        return (
            CheckSeverity.ERROR,
            f"Connection refused by {host}:{port}",
            [
                "Port is closed — check if the service is running",
                "Check firewall settings",
            ],
        )
    elif error_code == 113:  # No route to host
        return (
            CheckSeverity.CRITICAL,
            f"No route to host {host}:{port}",
            [
                "No route to host",
                "Check routing table: ip route",
                "Verify host is reachable on the network",
                "Check gateway settings",
            ],
        )
    elif error_code in (-2, -3):  # Name resolution errors
        return (
            CheckSeverity.CRITICAL,
            f"DNS resolution failed for {host}",
            [
                "Check DNS server settings",
                "Try: dig <domain> or nslookup <domain>",
                "Check /etc/resolv.conf",
            ],
        )
    else:
        return (
            CheckSeverity.ERROR,
            f"OS error connecting to {host}:{port}: {e}",
            [
                f"Error code: {error_code}",
                "Check network settings and server reachability",
            ],
        )
