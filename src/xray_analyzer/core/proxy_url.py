"""Shared helpers for constructing proxy URLs."""

from xray_analyzer.core.models import ProxyInfo


def build_proxy_url(proxy: ProxyInfo) -> str:
    """Build a ``protocol://server:port`` URL from full proxy info."""
    return f"{proxy.protocol.lower()}://{proxy.server}:{proxy.port}"
