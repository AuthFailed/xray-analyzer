# Xray Analyzer

Advanced diagnostics tool for Xray proxy servers with DNS, TCP, tunnel, and RKN blocking checks.

## Features

- **DNS Diagnostics** — проверка разрешения доменных имён
- **TCP Connection Checks** — проверка подключения с обработкой тайм-аутов и отказов
- **Proxy Tunnel Verification** — проверка работы прокси-туннеля
- **RKN Block Check** — проверка блокировки домена Роскомнадзором через API rknweb.ru
- **Telegram Notifications** — уведомления о проблемах
- **Structured Logging** — детальное логирование всех проверок
- **Docker Support** — быстрое развёртывание

## Quick Start

### Docker Compose (recommended)

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

### Local Development

```bash
# Install dependencies
uv sync

# Run full analysis (against local checker)
uv run xray-analyzer analyze

# Check a single host
uv run xray-analyzer check example.com --port 443

# Show checker API status
uv run xray-analyzer status

# Test web resources for censorship/blocking
uv run xray-analyzer censor-check
uv run xray-analyzer censor-check --domains google.com youtube.com --proxy socks5://127.0.0.1:1080

# Continuous monitoring
uv run xray-analyzer analyze --watch
```

## Configuration

See `.env.example` for all available options:

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKER_API_URL` | `https://xray-checker.kutovoy.dev` | Xray Checker API URL |
| `CHECKER_API_USERNAME` | | Basic auth username |
| `CHECKER_API_PASSWORD` | | Basic auth password |
| `DNS_TIMEOUT` | `5` | DNS resolution timeout (seconds) |
| `TCP_TIMEOUT` | `5` | TCP connection timeout (seconds) |
| `RKN_CHECK_ENABLED` | `true` | Enable RKN blocking checks |
| `TUNNEL_TEST_ENABLED` | `true` | Enable proxy tunnel tests |
| `NOTIFY_TELEGRAM_ENABLED` | `false` | Enable Telegram notifications |
| `TELEGRAM_BOT_TOKEN` | | Telegram bot token |
| `TELEGRAM_CHAT_ID` | | Telegram chat ID |
| `CENSOR_CHECK_DOMAINS` | | Comma-separated domains (default: ~30 sites) |
| `CENSOR_CHECK_TIMEOUT` | `4` | Timeout per domain (seconds) |
| `CENSOR_CHECK_MAX_PARALLEL` | `10` | Max parallel checks |
| `CENSOR_CHECK_PROXY_URL` | | Proxy URL for testing (empty = direct) |

## Docker

```bash
# Build and run
docker compose up -d

# View logs
docker compose logs -f
```

## Project Structure

```
src/xray_analyzer/
├── core/
│   ├── config.py        # Settings management
│   ├── logger.py        # Structured logging
│   ├── models.py        # Data models
│   ├── analyzer.py      # Main orchestrator
│   └── xray_client.py   # Xray Checker API client
├── diagnostics/
│   ├── dns_checker.py   # DNS resolution checks
│   ├── tcp_checker.py   # TCP connection tests
│   ├── tunnel_checker.py # Proxy tunnel verification
│   └── rkn_checker.py   # RKN blocking checks
├── notifiers/
│   ├── base.py          # Notifier interface
│   ├── telegram.py      # Telegram notifications
│   └── manager.py       # Notifier coordinator
└── cli.py               # CLI entry point
```
