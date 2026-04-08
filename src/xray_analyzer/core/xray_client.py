"""Async HTTP client for Xray Checker API."""

from typing import Any

import aiohttp
from aiohttp import BasicAuth

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import (
    CheckerConfigResponse,
    FullProxyResponse,
    ProxyStatusResponse,
    StatusSummaryResponse,
    SystemInfoResponse,
    SystemIPResponse,
)

log = get_logger("xray_checker_client")


class XrayCheckerClient:
    """Async client for interacting with the Xray Checker API."""

    def __init__(self) -> None:
        self.base_url = settings.checker_api_url.rstrip("/")
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an HTTP session with optional authentication."""
        if self._session is None or self._session.closed:
            headers: dict[str, str] = {}
            auth: BasicAuth | None = None

            if settings.is_api_protected:
                auth = BasicAuth(
                    login=settings.checker_api_username,
                    password=settings.checker_api_password,
                )
                log.info("Using Basic Authentication for API requests")

            self._session = aiohttp.ClientSession(
                headers=headers,
                auth=auth,
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make an HTTP request and return parsed JSON response."""
        session = await self._get_session()
        url = f"{self.base_url}{path}"
        log.debug("Making request", method=method, url=url)

        async with session.request(method, url, **kwargs) as response:
            data = await response.json()
            if response.status >= 400:
                error_msg = data.get("error", f"HTTP {response.status}")
                log.error("API request failed", error=error_msg, status=response.status)
                raise XrayCheckerAPIError(error_msg, response.status)
            return data  # type: ignore[return-value]

    async def check_health(self) -> bool:
        """Check service health."""
        session = await self._get_session()
        url = f"{self.base_url}/health"
        async with session.get(url) as response:
            return response.status == 200

    async def get_public_proxies(self) -> ProxyStatusResponse:
        """Get proxy status without sensitive data (public endpoint)."""
        data = await self._request("GET", "/api/v1/public/proxies")
        return ProxyStatusResponse.model_validate(data)

    async def get_all_proxies(self) -> FullProxyResponse:
        """Get full list of all proxies (requires auth)."""
        data = await self._request("GET", "/api/v1/proxies")
        return FullProxyResponse.model_validate(data)

    async def get_proxy_by_id(self, stable_id: str) -> dict[str, Any]:
        """Get information about a single proxy."""
        return await self._request("GET", f"/api/v1/proxies/{stable_id}")

    async def get_proxy_status_simple(self, stable_id: str) -> str:
        """Get simple status for a proxy (OK/Failed)."""
        session = await self._get_session()
        url = f"{self.base_url}/config/{stable_id}"
        async with session.get(url) as response:
            text = await response.text()
            if response.status == 200:
                return text.strip()
            raise XrayCheckerAPIError(text.strip(), response.status)

    async def get_status_summary(self) -> StatusSummaryResponse:
        """Get summary statistics of all proxies."""
        data = await self._request("GET", "/api/v1/status")
        return StatusSummaryResponse.model_validate(data)

    async def get_checker_config(self) -> CheckerConfigResponse:
        """Get current checker configuration."""
        data = await self._request("GET", "/api/v1/config")
        return CheckerConfigResponse.model_validate(data)

    async def get_system_info(self) -> SystemInfoResponse:
        """Get version and uptime information."""
        data = await self._request("GET", "/api/v1/system/info")
        return SystemInfoResponse.model_validate(data)

    async def get_system_ip(self) -> SystemIPResponse:
        """Get current external IP of the server."""
        data = await self._request("GET", "/api/v1/system/ip")
        return SystemIPResponse.model_validate(data)


class XrayCheckerAPIError(Exception):
    """Exception raised when the Xray Checker API returns an error."""

    def __init__(self, message: str, status_code: int = 500) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)
