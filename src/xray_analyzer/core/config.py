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

    # Check-Host.net API
    check_host_api_key: str = ""

    # Proxy Status/IP Check URLs
    proxy_status_check_url: str = "http://cp.cloudflare.com/generate_204"
    proxy_ip_check_url: str = "https://api.ipify.org?format=text"

    # RKN Check
    rkn_api_url: str = Field(default="https://rknweb.ru/api")
    rkn_check_enabled: bool = True

    # Proxy SNI Check
    proxy_sni_test_enabled: bool = True
    proxy_sni_domain: str = "max.ru"

    # RKN Throttle Check (16-20KB DPI blocking)
    rkn_throttle_check_enabled: bool = True

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

    # Xray core for VLESS/Trojan/SS testing
    xray_binary_path: str = "xray"  # Path to xray binary (or "xray" if in PATH)
    xray_test_enabled: bool = True
    subscription_url: str = ""  # Subscription URL with VLESS/Trojan/SS share links
    subscription_hwid: str = ""  # HWID header for subscription (x-hwid)

    @property
    def is_api_protected(self) -> bool:
        """Check if the API requires authentication."""
        return bool(self.checker_api_username and self.checker_api_password)


settings = Settings()
