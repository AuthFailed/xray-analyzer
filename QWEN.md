# Xray Analyzer — Project Context

## Project Overview

**Xray Analyzer** is an advanced diagnostics tool for Xray proxy servers. It provides comprehensive health checks including DNS resolution (with Check-Host.net comparison), TCP connectivity and ping, RKN blocking detection (domains + IPs), proxy tunnel verification, exit IP checks, SNI connectivity tests, and full VLESS/Trojan/Shadowsocks proxy testing via Xray core. The tool works alongside `xray-checker` (a separate proxy monitoring service) and can send Telegram notifications when issues are detected.

### Key Features

- **DNS Diagnostics** — domain name resolution with Check-Host.net comparison (detects DNS poisoning, geo-blocking)
- **TCP Connection Checks** — connectivity testing with timeout and failure handling
- **TCP Ping** — latency measurement (min/max/avg, packet loss)
- **RKN Block Check** — checks if domains or IPs are blocked by Roskomnadzor via rknweb.ru API
- **Proxy Tunnel Verification** — proxy tunnel functionality testing for HTTP/SOCKS
- **Proxy Exit IP Check** — verifies exit IP through proxy via configured URL
- **Proxy SNI Check** — tests TLS connection through proxy to a known non-blocked domain (default: max.ru)
- **VLESS/Trojan/Shadowsocks Testing via Xray Core** — full proxy testing by launching Xray subprocess with REALITY/TLS/XTLS support
- **Xray Auto-Download** — automatically downloads latest Xray binary from GitHub releases if not found
- **Subscription URL Parsing** — fetches and parses subscription URLs (with HWID support) to get VLESS/Trojan/SS share links
- **Telegram Notifications** — alerts when problems are detected
- **Structured Logging** — detailed logging of all checks to console and file
- **Docker Support** — easy deployment via Docker Compose alongside xray-checker

## Tech Stack

| Category | Technology |
|----------|------------|
| Language | Python 3.14+ |
| Package Manager | `uv` |
| HTTP Client | `aiohttp` (async) |
| Validation | `pydantic` + `pydantic-settings` |
| CLI | `argparse` + `rich` (colored output, tables, panels) |
| Logging | `structlog` (JSON + console/file handlers) |
| Testing | `pytest` + `pytest-asyncio` + `aioresponses` |
| Linting | `ruff` |
| Containerization | Docker + Docker Compose |

## Project Structure

```
src/xray_analyzer/
├── core/
│   ├── config.py            # Settings management (pydantic-settings, loads from .env)
│   ├── logger.py            # Structured logging setup (structlog)
│   ├── models.py            # Pydantic data models (API responses, diagnostics)
│   ├── analyzer.py          # Main orchestrator (runs all checks on proxies)
│   └── xray_client.py       # Async HTTP client for Xray Checker API
├── diagnostics/
│   ├── dns_checker.py       # DNS resolution + Check-Host.net comparison
│   ├── tcp_checker.py       # TCP connection tests
│   ├── tcp_ping_checker.py  # TCP ping with latency statistics
│   ├── tunnel_checker.py    # Legacy proxy tunnel verification (HTTP/SOCKS)
│   ├── rkn_checker.py       # RKN blocking checks (domains + IPs)
│   ├── proxy_tcp_checker.py # TCP tunnel check through proxy to status URL
│   ├── proxy_ip_checker.py  # Exit IP check through proxy
│   ├── proxy_sni_checker.py # SNI/TLS connection check through proxy
│   ├── proxy_rkn_throttle_checker.py # RKN DPI throttle detection (16-20KB cutoff)
│   ├── proxy_cross_checker.py # Cross-proxy connectivity tests (HTTP/SOCKS + Xray)
│   ├── proxy_xray_checker.py # VLESS/Trojan/SS testing via Xray core
│   ├── subscription_parser.py # Subscription URL fetching and share URL parsing
│   ├── xray_manager.py      # Xray subprocess management (config generation, start/stop)
│   └── xray_downloader.py   # Auto-download Xray from GitHub releases
├── notifiers/
│   ├── base.py              # Notifier interface
│   ├── telegram.py          # Telegram notifications
│   └── manager.py           # Notifier coordinator
└── cli.py                   # CLI entry point (argparse + rich)

tests/
├── test_dns_checker.py           # DNS checker tests
├── test_new_checks.py            # Tests for TCP ping, RKN, IP detection
├── test_rkn_throttle_checker.py  # Tests for RKN DPI throttle detection
├── test_proxy_cross_checker.py   # Cross-proxy connectivity tests
├── test_proxy_xray_checker.py    # Xray proxy tests
├── test_telegram_notifier.py     # Telegram notifier tests
└── test_xray_cross_connectivity.py # Xray cross-connectivity tests
```

## Building and Running

### Prerequisites

- Python 3.14+
- `uv` package manager (for local development)
- Docker & Docker Compose (for containerized deployment)
- Xray core binary (auto-downloaded from GitHub if not found)

### Local Development

```bash
# Install dependencies
uv sync

# Run full analysis (against configured checker API)
uv run xray-analyzer analyze

# Check a single host
uv run xray-analyzer check example.com --port 443

# Check a single host with proxy testing
uv run xray-analyzer check example.com --port 443 --proxy-url socks5://127.0.0.1:1080

# Show checker API status
uv run xray-analyzer status

# Continuous monitoring (runs at CHECK_INTERVAL_SECONDS interval)
uv run xray-analyzer analyze --watch
```

### Docker Compose (Recommended)

Both xray-checker and xray-analyzer run together:

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env — at minimum set SUBSCRIPTION_URL and SUBSCRIPTION_HWID

# Start both services
docker compose up -d

# View logs
docker compose logs -f xray-analyzer
docker compose logs -f xray-checker
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov

# Run specific test file
uv run pytest tests/test_dns_checker.py
```

### Linting

```bash
# Run ruff linter
uv run ruff check .

# Auto-fix
uv run ruff check . --fix
```

## Configuration

All configuration is managed via `.env` file (see `.env.example` for reference):

### Xray Checker API

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKER_API_URL` | `https://xray-checker.kutovoy.dev` | Xray Checker API URL |
| `CHECKER_API_USERNAME` | — | Basic auth username |
| `CHECKER_API_PASSWORD` | — | Basic auth password |

### Diagnostics

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_TIMEOUT` | `5` | DNS resolution timeout (seconds) |
| `TCP_TIMEOUT` | `5` | TCP connection timeout (seconds) |
| `TUNNEL_TEST_URL` | `https://httpbin.org/ip` | URL for legacy tunnel test |
| `TUNNEL_TEST_ENABLED` | `true` | Enable legacy proxy tunnel tests (HTTP/SOCKS only) |

### Check-Host.net

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_HOST_API_KEY` | — | API key (optional) for Check-Host.net |

### Proxy Status/IP Checks

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_STATUS_CHECK_URL` | `http://cp.cloudflare.com/generate_204` | URL for proxy status verification (should return HTTP 204/200) |
| `PROXY_IP_CHECK_URL` | `https://api.ipify.org?format=text` | URL for exit IP verification (should return plain text IP) |

### RKN Check

| Variable | Default | Description |
|----------|---------|-------------|
| `RKN_API_URL` | `https://rknweb.ru/api` | RKN API URL |
| `RKN_CHECK_ENABLED` | `false` | Enable RKN blocking checks (disabled by default — rknweb.ru API often unavailable) |

### Proxy SNI Check

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_SNI_TEST_ENABLED` | `true` | Enable SNI connection test through proxy |
| `PROXY_SNI_DOMAIN` | `max.ru` | Domain for SNI testing (should be known non-blocked) |

### RKN Throttle Check (DPI 16-20KB Blocking)

| Variable | Default | Description |
|----------|---------|-------------|
| `RKN_THROTTLE_CHECK_ENABLED` | `true` | Enable RKN DPI throttle detection (detects 16-20KB cutoff pattern) |

### Xray Core (VLESS/Trojan/SS Testing)

| Variable | Default | Description |
|----------|---------|-------------|
| `XRAY_BINARY_PATH` | `xray` | Path to Xray binary (auto-downloaded if not found) |
| `XRAY_TEST_ENABLED` | `true` | Enable Xray-based proxy testing for VLESS/Trojan/SS |
| `SUBSCRIPTION_URL` | — | Subscription URL with VLESS/Trojan/SS share links (supports multiple URLs via comma delimiter) |
| `SUBSCRIPTION_HWID` | — | HWID header (`x-hwid`) for subscription (if required) |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG` for verbose) |
| `LOG_FILE` | `xray-analyzer.log` | Log file path |

### Notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `NOTIFY_TELEGRAM_ENABLED` | `false` | Enable Telegram notifications |
| `TELEGRAM_BOT_TOKEN` | — | Telegram bot token |
| `TELEGRAM_CHAT_ID` | — | Telegram chat ID |

### Scheduling

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_INTERVAL_SECONDS` | `300` | Interval between checks in watch mode |
| `ANALYZE_ONLINE_PROXIES` | `false` | If true, analyzes all proxies (not just offline) |

## CLI Commands

| Command | Description |
|---------|-------------|
| `xray-analyzer analyze` | Run full analysis on all (offline) proxies |
| `xray-analyzer analyze --watch` | Continuous monitoring mode |
| `xray-analyzer check <host> --port <port>` | Check a single host |
| `xray-analyzer status` | Show checker API status (health, system info, proxy summary) |

## Diagnostic Checks Per Proxy

### For All Proxies (HTTP/SOCKS/VLESS/Trojan/SS)

1. **DNS Resolution (Check-Host)** — Resolves domain locally and compares with Check-Host.net (3 nodes). Detects DNS poisoning, geo-blocking.
2. **TCP Connection** — Tests connectivity to server:port.
3. **TCP Ping** — Measures latency (min/max/avg) and packet loss over 3 attempts.
4. **RKN Block Check (Domain)** — Checks if the domain is in Roskomnadzor's block list.
5. **RKN Block Check (IP)** — Checks resolved IPs against RKN block list.

### For HTTP/SOCKS Proxies

6. **Proxy TCP Tunnel** — Routes HTTP request through proxy to `PROXY_STATUS_CHECK_URL`.
7. **Proxy Exit IP** — Determines exit IP through proxy via `PROXY_IP_CHECK_URL`.
8. **Proxy SNI Connection** — Tests TLS connection through proxy to `PROXY_SNI_DOMAIN`.
9. **Legacy Tunnel Test** — Original tunnel check (backward compatibility).

### For VLESS/Trojan/Shadowsocks Proxies (via Xray Core)

6. **Proxy Xray Connectivity** — Launches Xray with REALITY/TLS config, tests connection through local SOCKS tunnel.
7. **Proxy Exit IP (Xray)** — Determines exit IP through Xray-managed tunnel.
8. **Proxy SNI Connection (Xray)** — Tests TLS connection through Xray tunnel to SNI domain.

### Cross-Proxy Tests (for problematic hosts)

When problems are detected, additional cross-tests are run using working proxies to determine if the issue is with the target server or the local infrastructure:

9. **RKN Throttle Check (Direct)** — Tests if the host is subject to DPI throttling (16-20KB cutoff) by making a range request and checking if connection is terminated after ~16KB.
10. **Cross-Proxy Connectivity (HTTP/SOCKS)** — Tests connectivity to problematic hosts through a working HTTP/SOCKS proxy.
11. **RKN Throttle Check (via Proxy)** — Re-runs throttle check through a working proxy to determine if the throttle can be bypassed.
12. **Cross-Proxy Connectivity (Xray)** — Tests connectivity to problematic VLESS/Trojan/SS hosts through a working Xray proxy.

## Architecture Notes

1. **XrayAnalyzer** class in `analyzer.py` is the main orchestrator. It fetches proxies from the checker API, filters offline ones by default, and runs diagnostic checks concurrently using `asyncio.gather`.

2. **Xray auto-download:** On startup, the analyzer checks if the Xray binary is available. If not found in PATH or `XRAY_BINARY_PATH`, it downloads the latest version from GitHub releases (XTLS/Xray-core) to `~/.local/share/xray/`.

3. **Subscription parsing:** The analyzer fetches the subscription URL (with `x-hwid` header if configured), decodes base64 content, and parses VLESS/Trojan/SS share URLs. Multiple subscription URLs can be specified via comma delimiter. Matching to checker API proxies uses 5 strategies: exact server:port, server+protocol, name matching (emoji-stripped), server-only, and port range.

4. **Xray subprocess management:** For VLESS/Trojan/SS proxies, Xray is launched with a generated JSON config containing the outbound (from share URL) and a local SOCKS inbound. After testing, the subprocess is terminated and the config file is cleaned up.

5. **Virtual hosts** (`virt.host`, `localhost`, `127.0.0.1`) are completely skipped — no checks are run.

6. **API Authentication:** The tool supports both public (unauthenticated) and full (authenticated) API endpoints. Public endpoint returns limited data (no server addresses), so auth credentials are recommended for full diagnostics. The analyzer tries the full endpoint first, then falls back to the public endpoint if unavailable.

7. **Retry logic:** The analyzer retries API calls up to 5 times with a 5-second delay before giving up.

8. **Notifications:** When problematic hosts are found, the NotifierManager coordinates sending alerts through configured notifiers (e.g., Telegram).

9. **Cross-proxy testing:** When problems are detected, the analyzer automatically runs cross-tests using working HTTP/SOCKS or Xray proxies to determine if issues are server-side or infrastructure-side. Results are added to the diagnostic with recommendations.

10. **Protocol-specific testing:** HTTP/SOCKS proxies use aiohttp-based checks. VLESS/Trojan/SS proxies require subscription URL configuration and use Xray core for testing.

## CLI Output Format

The analyzer provides a structured output with three sections:

1. **Summary Panel** — Total hosts, OK count, problem count with color-coded border.
2. **Problem Hosts** — Detailed breakdown of failed checks with messages, key details (IPs, latency, exit IP), and recommendations.
3. **Passing Hosts** — Compact table with status icons (✓/✗/⏱/–) per check type.
4. **Detailed Results** — Full check-by-check output for all hosts with extracted details.

```
╭───────────────────────────── Результат анализа ──────────────────────────────╮
│ Всего хостов: 2  |  ✓ OK: 1  |  ✗ PROBLEMS: 0                                │
╰──────────────────────────────────────────────────────────────────────────────╯

⚠ ХОСТЫ С ПРОБЛЕМАМИ

  → agaodfs.quazar.icu:443
  ────────────────────────────────────────────────────────────
    ✗ FAIL Proxy Xray Connectivity
      🇫🇷 Франция (vless): таймаут подключения
      Что делать:
      → Xray не смог подключиться через прокси
```

## Coding Conventions

- **Type hints** are used throughout (Python 3.14+ syntax)
- **Pydantic v2** for data validation with `model_config`
- **Async/await** for all I/O operations
- **Line length:** 120 characters (ruff config)
- **Ruff rules:** E, F, W, I, N, UP, B, A, C4, SIM, ARG, PTH, ERA, PL, RUF
- **Ignored rules:** PLR0913, PLR2004, PLR0911, PLR0912, PLR0915, RUF001
- **Tests:** async tests with `pytest-asyncio` in auto mode
