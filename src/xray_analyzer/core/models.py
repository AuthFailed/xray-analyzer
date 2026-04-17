"""Data models for diagnostics."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


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
