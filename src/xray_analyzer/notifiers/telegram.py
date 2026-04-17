"""Telegram notifier for diagnostic alerts."""

import aiohttp

from xray_analyzer.core.config import Settings
from xray_analyzer.core.config import settings as default_settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import (
    CheckStatus,
    HostDiagnostic,
)
from xray_analyzer.notifiers.base import Notifier

log = get_logger("telegram_notifier")

TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"

# Maximum message length for Telegram (4096 chars)
MAX_MESSAGE_LENGTH = 4000

# Ping thresholds (ms)
PING_GOOD_THRESHOLD = 100
PING_HIGH_THRESHOLD = 300


def _format_dns_check(details: dict) -> list[str]:
    """Format DNS check result into lines showing local vs Check-Host IPs."""
    lines = []

    local_ips = details.get("local_ips", [])
    checkhost_ips = details.get("checkhost_ips", [])

    # Show local IPs
    if local_ips:
        for ip in local_ips[:3]:  # Limit to 3
            lines.append(f"   🖥 Local DNS: {ip}")

    # Show Check-Host IPs
    if checkhost_ips:
        for ip in checkhost_ips[:3]:  # Limit to 3
            lines.append(f"   🌐 Check-Host: {ip}")

    # Show mismatch warning
    common = set(local_ips) & set(checkhost_ips)
    if not common and local_ips and checkhost_ips:
        lines.append("   ⚠️ IPs don't match — possible DNS spoofing or geo-blocking")

    if not lines:
        lines.append("   no data")

    return lines


def _format_tcp_ping(details: dict) -> str:
    """Format TCP ping result into compact status string."""
    latency_avg = details.get("latency_avg_ms")
    packet_loss = details.get("packet_loss_pct")

    if latency_avg is None and packet_loss is None:
        return "no data"

    parts = []

    if latency_avg is not None:
        if packet_loss and packet_loss > 0:
            parts.append(f"{int(latency_avg)}ms (loss {int(packet_loss)}%)")
        else:
            parts.append(f"{int(latency_avg)}ms")

    if packet_loss is not None and packet_loss > 0:
        if packet_loss >= 50:
            return f"🔴 critical loss {int(packet_loss)}%"
        elif packet_loss >= 20:
            return f"🟡 loss {int(packet_loss)}%"

    if latency_avg is not None:
        if latency_avg > PING_HIGH_THRESHOLD:
            return f"🟡 high {parts[0]}"
        elif latency_avg > PING_GOOD_THRESHOLD:
            return parts[0]
        else:
            return f"✓ {parts[0]}"

    return parts[0] if parts else "no data"


def _format_check_result(check) -> str | list[str]:
    """Format a single check result into compact line(s).

    Returns either a string (single line) or list of strings (multi-line for DNS).
    """
    check_name = check.check_name.replace("Proxy ", "").replace(" Check", "")

    # Skip checks - show them now
    if check.status == CheckStatus.SKIP:
        skip_reason = check.message[:80] if check.message else "skipped"
        return f"○ {check_name}: skipped — {skip_reason}"

    # Passed checks
    if check.status == CheckStatus.PASS:
        if "dns resolution" in check.check_name.lower():
            lines = [f"✓ {check_name}: DNS resolved"]
            dns_lines = _format_dns_check(check.details)
            lines.extend(dns_lines)
            return lines
        elif "ping" in check.check_name.lower():
            ping_status = _format_tcp_ping(check.details)
            return f"• {check_name}: {ping_status}"
        elif "tcp connection" in check.check_name.lower():
            return f"• {check_name}: ✓ reachable (TCP connection check)"
        elif "exit ip" in check.check_name.lower():
            exit_ip = check.details.get("exit_ip", "no data")
            return f"• {check_name}: {exit_ip}"
        elif "rkn" in check.check_name.lower():
            return f"• {check_name}: ✓ not blocked"
        elif "sni" in check.check_name.lower():
            return f"• {check_name}: ✓ connected"
        elif "tunnel" in check.check_name.lower():
            return f"• {check_name}: ✓ tunnel working"
        elif "cross-proxy" in check.check_name.lower() or "cross" in check.check_name.lower():
            working_proxy = check.details.get("working_proxy", "unknown")
            return f"• {check_name}: ✓ reachable via {working_proxy} (Xray) — server works, possible blocking"
        elif "connectivity" in check.check_name.lower():
            return f"• {check_name}: ✓ connected"
        else:
            return f"• {check_name}: ✓ OK"

    # Failed/timeout checks
    if check.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT):
        icon = "❌" if check.status == CheckStatus.FAIL else "⏱"

        # Extract short error message
        error_msg = check.message
        if len(error_msg) > 80:
            error_msg = error_msg[:77] + "..."

        # Build compact details
        detail_parts = []
        if "protocol" in check.details:
            detail_parts.append(check.details["protocol"])
        if "exit_ip" in check.details:
            detail_parts.append(f"IP: {check.details['exit_ip']}")
        if "http_status" in check.details:
            detail_parts.append(f"HTTP {check.details['http_status']}")

        detail_str = f" ({', '.join(detail_parts)})" if detail_parts else ""

        # Cross-proxy connectivity - explain what this test does
        if "cross-proxy" in check.check_name.lower() or "cross" in check.check_name.lower():
            working_proxy = check.details.get("working_proxy", "unknown")
            if check.status == CheckStatus.PASS:
                return f"✓ {check_name}: ✓ reachable via {working_proxy} (Xray) — server works, possible blocking"
            else:
                return f"{icon} {check_name}: unreachable via {working_proxy} (Xray) — server may be down"

        # Xray connectivity with label suffix (IP fallback)
        if "connectivity" in check.check_name.lower():
            label_suffix = ""
            if "(ip:" in check.check_name.lower():
                label_suffix = " — IP fallback (domain test failed)"
            else:
                label_suffix = " — primary Xray check"
            return f"{icon} {check_name}: {error_msg}{detail_str}{label_suffix}"

        return f"{icon} {check_name}: {error_msg}{detail_str}"

    return f"• {check_name}: {check.message}"


def _format_recommendations(diag: HostDiagnostic) -> str:
    """Format recommendations into compact lines."""
    recs = []

    # Collect recommendations from all failed checks
    for result in diag.results:
        if result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT):
            recs.extend(result.recommendations)

    # Add host-level recommendations
    recs.extend(diag.recommendations)

    if not recs:
        return ""

    # Deduplicate and limit
    unique_recs = list(dict.fromkeys(recs))[:3]

    return "🔧 " + "\n🔧 ".join(unique_recs)


class TelegramNotifier(Notifier):
    """Send diagnostic alerts via Telegram Bot API."""

    def __init__(self, settings: Settings | None = None) -> None:
        cfg = settings or default_settings
        self.bot_token = cfg.telegram_bot_token
        self.chat_id = cfg.telegram_chat_id
        self.enabled = cfg.notify_telegram_enabled

    async def send_notification(self, diagnostics: list[HostDiagnostic]) -> bool:
        """Send Telegram notification with diagnostic summary."""
        if not self.enabled or not self.bot_token or not self.chat_id:
            log.debug("Telegram notifications disabled or not configured")
            return False

        # Only notify if there are actual problems
        problematic = [d for d in diagnostics if d.overall_status != CheckStatus.PASS]
        if not problematic:
            log.info("No problems to report, skipping notification")
            return True

        message = self._build_message(problematic, diagnostics)

        try:
            url = TELEGRAM_API_URL.format(token=self.bot_token)
            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }

            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response,
            ):
                if response.status == 200:
                    log.info(
                        "Telegram notification sent",
                        hosts_count=len(problematic),
                    )
                    return True
                else:
                    error_text = await response.text()
                    log.error(
                        "Failed to send Telegram notification",
                        status=response.status,
                        error=error_text,
                    )
                    return False

        except TimeoutError:
            log.error("Telegram notification timed out")
            return False
        except Exception as e:
            log.error("Error sending Telegram notification", error=str(e))
            return False

    def _build_message(
        self,
        problematic: list[HostDiagnostic],
        all_diagnostics: list[HostDiagnostic],
    ) -> str:
        """Build compact HTML message from diagnostics."""
        lines = [
            "<b>🔍 Xray Analyzer — Problems detected</b>",
            "",
            f"📊 Hosts checked: <code>{len(all_diagnostics)}</code>",
            f"❌ With problems: <code>{len(problematic)}</code>",
            f"✅ OK: <code>{len(all_diagnostics) - len(problematic)}</code>",
            "",
            "━" * 25,
            "",
        ]

        for idx, diag in enumerate(problematic, 1):
            # Extract hostname
            host = diag.host

            # Filter results: show failed, timeout, and skipped checks
            relevant_checks = [
                r for r in diag.results if r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT, CheckStatus.SKIP)
            ]

            if not relevant_checks:
                continue

            # Host header
            lines.append(f"<b>{idx}. {host}</b>")
            lines.append("")

            # Test results
            lines.append("<b>Tests:</b>")
            check_idx = 1
            for check in diag.results:
                formatted = _format_check_result(check)
                if formatted is None:
                    continue

                # Handle multi-line results (like DNS with IP breakdown)
                if isinstance(formatted, list):
                    for line in formatted:
                        lines.append(f"{check_idx}. {line}")
                    check_idx += 1
                else:
                    lines.append(f"{check_idx}. {formatted}")
                    check_idx += 1

            lines.append("")

            # Recommendations
            recs = _format_recommendations(diag)
            if recs:
                lines.append("<b>What to check:</b>")
                lines.append(recs)

            # Separator between hosts (except last)
            if idx < len(problematic):
                lines.append("")
                lines.append("─" * 20)
                lines.append("")

        # Footer
        lines.append("")
        lines.append("━" * 25)
        lines.append("💡 <i>Full report: xray-analyzer analyze</i>")

        message = "\n".join(lines)

        # Truncate if too long for Telegram
        if len(message) > MAX_MESSAGE_LENGTH:
            message = message[:MAX_MESSAGE_LENGTH] + "\n\n⚠️ <i>Message truncated</i>"

        return message
