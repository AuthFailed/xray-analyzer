"""Configuration management using pydantic-settings."""


from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Xray Checker API
    checker_api_url: str = Field(default="https://xray-checker.kutovoy.dev")
    checker_api_username: str = ""
    checker_api_password: str = ""

    # Diagnostics
    dns_timeout: int = Field(default=5, ge=1, le=30)
    tcp_timeout: int = Field(default=5, ge=1, le=30)
    tunnel_test_url: str = "https://httpbin.org/ip"
    tunnel_test_enabled: bool = True

    # RKN Check
    rkn_api_url: str = Field(default="https://rknweb.ru/api")
    rkn_check_enabled: bool = True

    # Logging
    log_level: str = "INFO"
    log_file: str = "xray-analyzer.log"

    # Notifications
    notify_telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    # Scheduling
    check_interval_seconds: int = Field(default=300, ge=60)

    # Analysis scope
    analyze_online_proxies: bool = False

    @property
    def is_api_protected(self) -> bool:
        """Check if the API requires authentication."""
        return bool(self.checker_api_username and self.checker_api_password)


settings = Settings()
