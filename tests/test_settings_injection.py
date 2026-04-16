"""Verify top-level classes accept an injected Settings without touching the singleton."""

from xray_analyzer.core.analyzer import XrayAnalyzer
from xray_analyzer.core.config import Settings
from xray_analyzer.core.xray_client import XrayCheckerClient
from xray_analyzer.notifiers.manager import NotifierManager
from xray_analyzer.notifiers.telegram import TelegramNotifier


def test_xray_client_uses_injected_settings():
    cfg = Settings(checker_api_url="https://override.example/api/")
    client = XrayCheckerClient(settings=cfg)
    assert client.base_url == "https://override.example/api"


def test_telegram_notifier_uses_injected_settings():
    cfg = Settings(
        telegram_bot_token="test-token",
        telegram_chat_id="42",
        notify_telegram_enabled=True,
    )
    notifier = TelegramNotifier(settings=cfg)
    assert notifier.bot_token == "test-token"
    assert notifier.chat_id == "42"
    assert notifier.enabled is True


def test_notifier_manager_respects_injected_settings():
    disabled = Settings(notify_telegram_enabled=False)
    assert NotifierManager(settings=disabled).notifiers == []

    enabled = Settings(notify_telegram_enabled=True, telegram_bot_token="x", telegram_chat_id="1")
    manager = NotifierManager(settings=enabled)
    assert len(manager.notifiers) == 1
    assert isinstance(manager.notifiers[0], TelegramNotifier)


def test_analyzer_threads_settings_into_subcomponents():
    cfg = Settings(checker_api_url="https://custom.example/")
    analyzer = XrayAnalyzer(settings=cfg)
    assert analyzer._settings is cfg
    assert analyzer.client.base_url == "https://custom.example"
