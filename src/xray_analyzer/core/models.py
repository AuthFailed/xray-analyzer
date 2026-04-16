"""Data models for API responses and diagnostics."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# --- Xray Checker API Models ---


class ProxyStatus(BaseModel):
    """Simplified proxy status (public endpoint)."""

    model_config = ConfigDict(populate_by_name=True)

    stable_id: str = Field(alias="stableId")
    name: str
    online: bool
    latency_ms: int = Field(alias="latencyMs")


class ProxyInfo(BaseModel):
    """Information about a single proxy from the checker API."""

    model_config = ConfigDict(populate_by_name=True)

    index: int
    stable_id: str = Field(alias="stableId")
    name: str
    sub_name: str = Field(alias="subName")
    server: str
    port: int
    protocol: str
    proxy_port: int = Field(alias="proxyPort")
    online: bool
    latency_ms: int = Field(alias="latencyMs")


class ProxyStatusResponse(BaseModel):
    """Response from /api/v1/public/proxies."""

    success: bool
    data: list[ProxyStatus]


class FullProxyResponse(BaseModel):
    """Response from /api/v1/proxies."""

    success: bool
    data: list[ProxyInfo]


class StatusSummary(BaseModel):
    """Summary statistics from /api/v1/status."""

    model_config = ConfigDict(populate_by_name=True)

    total: int
    online: int
    offline: int
    avg_latency_ms: int = Field(alias="avgLatencyMs")


class StatusSummaryResponse(BaseModel):
    """Response from /api/v1/status."""

    success: bool
    data: StatusSummary


class SystemInfo(BaseModel):
    """System info from /api/v1/system/info."""

    model_config = ConfigDict(populate_by_name=True)

    version: str
    uptime: str
    uptime_sec: int = Field(alias="uptimeSec")
    instance: str


class SystemInfoResponse(BaseModel):
    """Response from /api/v1/system/info."""

    success: bool
    data: SystemInfo


class SystemIPResponse(BaseModel):
    """Response from /api/v1/system/ip."""

    success: bool
    data: dict[str, str]


# --- Diagnostics Models ---


class CheckSeverity(StrEnum):
    """Severity levels for diagnostic checks."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class CheckStatus(StrEnum):
    """Status of a diagnostic check."""

    PASS = "pass"
    WARN = "warn"  # non-critical issue worth noting, but not a blocker
    FAIL = "fail"
    SKIP = "skip"
    TIMEOUT = "timeout"


class DiagnosticResult(BaseModel):
    """Result of a single diagnostic check."""

    check_name: str
    status: CheckStatus
    severity: CheckSeverity
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_ms: float = 0.0


class HostDiagnostic(BaseModel):
    """Complete diagnostic report for a host."""

    host: str
    results: list[DiagnosticResult] = Field(default_factory=list)
    overall_status: CheckStatus = CheckStatus.PASS
    recommendations: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.now)

    def add_result(self, result: DiagnosticResult) -> None:
        """Add a diagnostic result and update overall status.

        Severity determines impact on overall_status:
          CRITICAL / ERROR + FAIL → always FAIL
          TIMEOUT              → always FAIL
          WARNING / INFO + FAIL → WARN  (only if currently PASS; won't downgrade FAIL)
        """
        self.results.append(result)
        if result.status == CheckStatus.TIMEOUT:
            self.overall_status = CheckStatus.FAIL
        elif result.status == CheckStatus.FAIL:
            is_hard_fail = result.severity in (CheckSeverity.CRITICAL, CheckSeverity.ERROR)
            if is_hard_fail:
                self.overall_status = CheckStatus.FAIL
            elif self.overall_status == CheckStatus.PASS:
                # Soft failure (WARNING/INFO) — surface as WARN, not FAIL
                self.overall_status = CheckStatus.WARN

    def add_recommendation(self, recommendation: str) -> None:
        """Add a recommendation for fixing issues."""
        self.recommendations.append(recommendation)

    def finalize_status(self) -> None:
        """Re-evaluate overall_status using authoritative signals.

        For a *proxy* host, the authoritative signal is whether the proxy itself
        accepts traffic — i.e. a passing "Proxy Xray Connectivity" check.
        Direct TCP/Ping/DNS to the server may legitimately fail (CDN routing,
        TCP fingerprint blocks, FakeDNS, etc.) while the proxy still works.

        Rules applied here:
          - If any "Proxy Xray Connectivity" passes → overall is at most WARN
            (downgrade FAIL → WARN). The host is functionally usable.
          - If "Proxy Xray Connectivity" itself failed/timed-out → keep FAIL.
          - Hosts with no proxy connectivity check at all are unaffected.
        """
        proxy_results = [r for r in self.results if r.check_name.startswith("Proxy Xray Connectivity")]
        if not proxy_results:
            return
        any_proxy_ok = any(r.status == CheckStatus.PASS for r in proxy_results)
        if any_proxy_ok and self.overall_status == CheckStatus.FAIL:
            self.overall_status = CheckStatus.WARN
