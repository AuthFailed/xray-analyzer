"""Base notifier interface."""

from abc import ABC, abstractmethod

from xray_analyzer.core.models import HostDiagnostic


class Notifier(ABC):
    """Base class for notification providers."""

    @abstractmethod
    async def send_notification(self, diagnostics: list[HostDiagnostic]) -> bool:
        """
        Send notification about problematic hosts.

        Returns True if notification was sent successfully.
        """
        ...
