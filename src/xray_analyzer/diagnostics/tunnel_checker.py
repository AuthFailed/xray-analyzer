"""Legacy proxy tunnel check — delegates to proxy_tcp_checker."""

from xray_analyzer.core.config import settings
from xray_analyzer.core.models import CheckSeverity, CheckStatus, DiagnosticResult
from xray_analyzer.diagnostics.proxy_tcp_checker import check_proxy_tcp_tunnel


async def check_proxy_tunnel(proxy_url: str, test_url: str | None = None) -> DiagnosticResult:
    """Check if traffic is properly routed through the proxy tunnel.

    Thin wrapper around `check_proxy_tcp_tunnel` kept for backwards compatibility
    and because it uses a different default test URL (`settings.tunnel_test_url`)
    and accepts any HTTP status as success (unlike the strict 200/204 check).
    """
    if not settings.tunnel_test_enabled:
        return DiagnosticResult(
            check_name="Proxy Tunnel",
            status=CheckStatus.SKIP,
            severity=CheckSeverity.INFO,
            message="Proxy tunnel check is disabled in configuration",
        )

    return await check_proxy_tcp_tunnel(
        proxy_url,
        test_url=test_url or settings.tunnel_test_url,
        check_name="Proxy Tunnel",
        accept_any_status=True,
    )
