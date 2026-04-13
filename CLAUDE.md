# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
uv sync

# Run all tests
uv run pytest

# Run a single test file
uv run pytest tests/test_censor_checker.py

# Run a single test by name
uv run pytest tests/test_censor_checker.py::TestIsRknSpoof::test_known_rkn_ip

# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format src/ tests/

# Run the CLI
uv run xray-analyzer analyze
uv run xray-analyzer analyze --watch
uv run xray-analyzer check example.com --port 443
uv run xray-analyzer status
uv run xray-analyzer censor-check
uv run xray-analyzer censor-check --domains google.com youtube.com --proxy socks5://127.0.0.1:1080
```

## Architecture

The tool is an async Python diagnostics engine for Xray proxy servers. It talks to an external **Xray Checker API** (configured via `CHECKER_API_URL`) to get proxy lists, then runs a battery of checks on each offline proxy.

### Data flow

1. `cli.py` — argparse entry point, dispatches to async `cmd_*` coroutines
2. `core/analyzer.py` (`XrayAnalyzer`) — main orchestrator; fetches proxies from Xray Checker API, runs all checks concurrently via `asyncio.gather`, then adds cross-proxy and RKN throttle checks for problematic hosts
3. `core/xray_client.py` — aiohttp client for the Xray Checker REST API
4. `diagnostics/` — individual check functions, each returning a `DiagnosticResult`
5. `notifiers/` — pluggable notifiers (Telegram); `NotifierManager` fans out to all enabled notifiers

### Check pipeline (per proxy)

For each proxy `_run_all_checks` runs sequentially:
1. DNS resolution with Check-Host.net comparison (`dns_checker.py`)
2. TCP connection (`tcp_checker.py`)
3. TCP ping (`tcp_ping_checker.py`)
4. RKN block check via rknweb.ru API (`rkn_checker.py`)
5. For **VLESS/Trojan/SS** proxies (if `SUBSCRIPTION_URL` configured): spawns an `XrayInstance` and tests connectivity (`proxy_xray_checker.py`, `xray_manager.py`)
6. For **HTTP/SOCKS** proxies: TCP tunnel, exit IP, SNI, and legacy tunnel checks

After all proxies are analyzed, the orchestrator runs additional cross-proxy checks on problematic hosts — testing them *through* a known-working proxy (HTTP/SOCKS or Xray) to distinguish local network issues from server-side failures. It also runs RKN DPI throttle checks (16–20 KB cutoff detection) both directly and through working proxies.

### Key models (`core/models.py`)

- `DiagnosticResult` — result of one check: `check_name`, `status` (`CheckStatus`), `severity` (`CheckSeverity`), `message`, `details` dict, `duration_ms`
- `HostDiagnostic` — aggregate for one host: list of `DiagnosticResult`, `overall_status`, `recommendations`
- `ProxyInfo` / `ProxyStatus` — proxy data from Xray Checker API

### Configuration (`core/config.py`)

All settings are loaded from `.env` via `pydantic-settings`. The singleton `settings` object is imported directly. Key non-obvious settings:
- `ANALYZE_ONLINE_PROXIES` — by default only offline proxies are analyzed
- `SUBSCRIPTION_URL` — required for VLESS/Trojan/SS testing; fetches share links used by `XrayInstance`
- `XRAY_BINARY_PATH` — path to xray binary; auto-downloaded if not found
- `RKN_THROTTLE_CHECK_ENABLED` — enables 16–20 KB DPI throttle detection

### Test conventions

Tests use `pytest-asyncio` with `asyncio_mode = "auto"`. HTTP mocking uses `aioresponses`. Tests live in `tests/` with one file per module.