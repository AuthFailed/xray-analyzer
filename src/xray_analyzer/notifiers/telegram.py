"""Telegram notifier for diagnostic alerts."""


import aiohttp

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import (
    CheckSeverity,
    CheckStatus,
    HostDiagnostic,
)
from xray_analyzer.notifiers.base import Notifier

log = get_logger("telegram_notifier")

TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


class TelegramNotifier(Notifier):
    """Send diagnostic alerts via Telegram Bot API."""

    def __init__(self) -> None:
        self.bot_token = settings.telegram_bot_token
        self.chat_id = settings.telegram_chat_id
        self.enabled = settings.notify_telegram_enabled

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

        message = self._build_message(problematic)

        try:
            url = TELEGRAM_API_URL.format(token=self.bot_token)
            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }

            async with aiohttp.ClientSession() as session, session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
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

    def _build_message(self, diagnostics: list[HostDiagnostic]) -> str:
        """Build HTML message from diagnostics."""
        lines = [
            "<b>🔍 Xray Analyzer — Обнаружены проблемы</b>",
            "",
            f"📊 Проанализировано хостов: <code>{len(diagnostics)}</code>",
            "",
        ]

        for diag in diagnostics:
            # Count issues
            failed_checks = [
                r for r in diag.results if r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            ]
            if not failed_checks:
                continue

            severity_emoji = {
                CheckSeverity.CRITICAL: "🚨",
                CheckSeverity.ERROR: "❌",
                CheckSeverity.WARNING: "⚠️",
                CheckSeverity.INFO: "ℹ️",
            }

            lines.append(f"<b>Хост: {diag.host}</b>")

            for check in failed_checks:
                emoji = severity_emoji.get(check.severity, "•")
                lines.append(f"  {emoji} <b>{check.check_name}</b>: {check.message}")

                # Add top 2 recommendations
                recommendations = check.details.get("recommendations", [])
                if not recommendations and hasattr(check, "recommendations"):
                    recommendations = check.recommendations

                if recommendations:
                    for rec in recommendations[:2]:
                        lines.append(f"    → {rec}")

            lines.append("")

        lines.append(
            "💡 <i>Запустите xray-analyzer для получения детального отчёта</i>"
        )

        return "\n".join(lines)
