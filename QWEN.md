# Xray Analyzer — Project Context

## Project Overview

**Xray Analyzer** is an advanced diagnostics tool for Xray proxy servers. It provides comprehensive health checks including DNS resolution, TCP connectivity, proxy tunnel verification, and RKN (Roskomnadzor) blocking detection. The tool is designed to work alongside `xray-checker` (a separate proxy monitoring service) and can send Telegram notifications when issues are detected.

### Key Features

- **DNS Diagnostics** — domain name resolution verification
- **TCP Connection Checks** — connectivity testing with timeout and failure handling
- **Proxy Tunnel Verification** — proxy tunnel functionality testing
- **RKN Block Check** — checks if domains are blocked by Roskomnadzor via rknweb.ru API
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
| CLI | `argparse` + `rich` (colored output, tables) |
| Logging | `structlog` (JSON + console/file handlers) |
| Testing | `pytest` + `pytest-asyncio` + `aioresponses` |
| Linting | `ruff` |
| Containerization | Docker + Docker Compose |

## Project Structure

```
src/xray_analyzer/
├── core/
│   ├── config.py        # Settings management (pydantic-settings, loads from .env)
│   ├── logger.py        # Structured logging setup (structlog)
│   ├── models.py        # Pydantic data models (API responses, diagnostics)
│   ├── analyzer.py      # Main orchestrator (runs all checks on proxies)
│   └── xray_client.py   # Async HTTP client for Xray Checker API
├── diagnostics/
│   ├── dns_checker.py   # DNS resolution checks
│   ├── tcp_checker.py   # TCP connection tests
│   ├── tunnel_checker.py # Proxy tunnel verification
│   └── rkn_checker.py   # RKN blocking checks
├── notifiers/
│   ├── base.py          # Notifier interface
│   ├── telegram.py      # Telegram notifications
│   └── manager.py       # Notifier coordinator
└── cli.py               # CLI entry point (argparse + rich)

tests/
└── test_dns_checker.py  # DNS checker tests
```

## Building and Running

### Prerequisites

- Python 3.14+
- `uv` package manager (for local development)
- Docker & Docker Compose (for containerized deployment)

### Local Development

```bash
# Install dependencies
uv sync

# Run full analysis (against configured checker API)
uv run xray-analyzer analyze

# Check a single host
uv run xray-analyzer check example.com --port 443

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
# Edit .env — at minimum set SUBSCRIPTION_URL

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

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKER_API_URL` | `https://xray-checker.kutovoy.dev` | Xray Checker API URL |
| `CHECKER_API_USERNAME` | — | Basic auth username |
| `CHECKER_API_PASSWORD` | — | Basic auth password |
| `DNS_TIMEOUT` | `5` | DNS resolution timeout (seconds) |
| `TCP_TIMEOUT` | `5` | TCP connection timeout (seconds) |
| `TUNNEL_TEST_URL` | `https://httpbin.org/ip` | URL for tunnel test |
| `TUNNEL_TEST_ENABLED` | `true` | Enable proxy tunnel tests |
| `RKN_API_URL` | `https://rknweb.ru/api` | RKN API URL |
| `RKN_CHECK_ENABLED` | `true` | Enable RKN blocking checks |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_FILE` | `xray-analyzer.log` | Log file path |
| `NOTIFY_TELEGRAM_ENABLED` | `false` | Enable Telegram notifications |
| `TELEGRAM_BOT_TOKEN` | — | Telegram bot token |
| `TELEGRAM_CHAT_ID` | — | Telegram chat ID |
| `CHECK_INTERVAL_SECONDS` | `300` | Interval between checks in watch mode |
| `ANALYZE_ONLINE_PROXIES` | `false` | If true, analyzes all proxies (not just offline) |

## CLI Commands

| Command | Description |
|---------|-------------|
| `xray-analyzer analyze` | Run full analysis on all (offline) proxies |
| `xray-analyzer analyze --watch` | Continuous monitoring mode |
| `xray-analyzer check <host> --port <port>` | Check a single host |
| `xray-analyzer status` | Show checker API status (health, system info, proxy summary) |

## Architecture Notes

1. **XrayAnalyzer** class in `analyzer.py` is the main orchestrator. It fetches proxies from the checker API, filters offline ones by default, and runs diagnostic checks concurrently using `asyncio.gather`.

2. **Diagnostic flow per proxy:**
   - DNS Resolution → if fails, skip remaining checks
   - TCP Connection
   - RKN Block Check
   - Proxy Tunnel Test (if enabled and proxy URL available)

3. **Virtual hosts** (`virt.host`, `localhost`, `127.0.0.1`) skip DNS and TCP checks.

4. **API Authentication:** The tool supports both public (unauthenticated) and full (authenticated) API endpoints. Public endpoint returns limited data (no server addresses), so auth credentials are recommended for full diagnostics.

5. **Retry logic:** The analyzer retries API calls up to 5 times with a 5-second delay before giving up.

6. **Notifications:** When problematic hosts are found, the NotifierManager coordinates sending alerts through configured notifiers (e.g., Telegram).

## Coding Conventions

- **Type hints** are used throughout (Python 3.14+ syntax)
- **Pydantic v2** for data validation with `model_config`
- **Async/await** for all I/O operations
- **Line length:** 120 characters (ruff config)
- **Ruff rules:** E, F, W, I, N, UP, B, A, C4, SIM, ARG, PTH, ERA, PL, RUF
- **Ignored rules:** PLR0913 (too many arguments), PLR2004 (magic values), PLR0911 (too many returns), RUF001 (ambiguous characters)
- **Tests:** async tests with `pytest-asyncio` in auto mode
