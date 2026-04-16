"""Notifier manager to coordinate multiple notification providers."""

from xray_analyzer.core.config import Settings
from xray_analyzer.core.config import settings as default_settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import HostDiagnostic
from xray_analyzer.notifiers.base import Notifier
from xray_analyzer.notifiers.telegram import TelegramNotifier

log = get_logger("notifier_manager")


class NotifierManager:
    """Manage and coordinate multiple notification providers."""

    def __init__(self, settings: Settings | None = None) -> None:
        cfg = settings or default_settings
        self.notifiers: list[Notifier] = []

        if cfg.notify_telegram_enabled:
            self.notifiers.append(TelegramNotifier(settings=cfg))
            log.info("Telegram notifier enabled")

    async def notify(self, diagnostics: list[HostDiagnostic]) -> None:
        """Send notifications through all configured providers."""
        if not self.notifiers:
            log.debug("No notifiers configured")
            return

        for notifier in self.notifiers:
            try:
                success = await notifier.send_notification(diagnostics)
                if success:
                    log.info(
                        "Notification sent successfully",
                        notifier=notifier.__class__.__name__,
                    )
                else:
                    log.warning(
                        "Failed to send notification",
                        notifier=notifier.__class__.__name__,
                    )
            except Exception as e:
                log.error(
                    "Error in notifier",
                    notifier=notifier.__class__.__name__,
                    error=str(e),
                    exc_info=True,
                )
