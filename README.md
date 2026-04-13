# Xray Analyzer

Advanced diagnostics tool for Xray proxy servers with DNS, TCP, tunnel, RKN blocking, DPI throttle, and censorship checks.

## Features

- **DNS Diagnostics** — сравнение локального DNS с Check-Host.net (обнаружение DNS poisoning)
- **TCP Connection & Ping** — проверка подключения и измерение задержки
- **Proxy Tunnel Verification** — проверка TCP-туннеля, exit IP и SNI через прокси
- **RKN Block Check** — проверка блокировки домена/IP через API rknweb.ru
- **RKN DPI Throttle Detection** — обнаружение троттлинга на 16–20 КБ
- **Xray Connectivity** — тестирование VLESS/Trojan/Shadowsocks через Xray core
- **Cross-Proxy Tests** — проверка доступности через рабочий прокси (разграничение локальных проблем и серверных)
- **Censorship Check** — массовая проверка доменов на блокировку (с поддержкой прокси)
- **Telegram Notifications** — уведомления о проблемах
- **Docker Support** — быстрое развёртывание

## Quick Start

### Docker Compose (recommended)

```bash
cp .env.example .env
# Edit .env — set SUBSCRIPTION_URL at minimum
docker compose up -d
docker compose logs -f xray-analyzer
```

### Local Development

```bash
uv sync
uv run xray-analyzer analyze
```

## CLI Reference

### `analyze` — полный анализ всех прокси из Xray Checker API

```bash
uv run xray-analyzer analyze
uv run xray-analyzer analyze --watch        # непрерывный мониторинг (интервал из CHECK_INTERVAL_SECONDS)
```

### `check` — диагностика одного хоста

```bash
uv run xray-analyzer check example.com
uv run xray-analyzer check example.com --port 8443
uv run xray-analyzer check example.com --proxy socks5://127.0.0.1:1080
uv run xray-analyzer check example.com --proxy http://user:pass@192.168.1.1:3128
```

| Аргумент | По умолчанию | Описание |
|----------|-------------|----------|
| `host` | — | Хост для проверки |
| `--port` | `443` | Порт |
| `--proxy` | — | URL прокси для маршрутизации проверок (TCP tunnel, exit IP, SNI, tunnel) |

### `status` — статус Xray Checker API

```bash
uv run xray-analyzer status
```

Выводит health check, версию, аптайм, сводку по прокси и IP сервера.

### `censor-check` — проверка доменов на блокировку

```bash
uv run xray-analyzer censor-check
uv run xray-analyzer censor-check --domains google.com youtube.com
uv run xray-analyzer censor-check --proxy socks5://127.0.0.1:1080
uv run xray-analyzer censor-check --domains google.com --proxy http://host:port --timeout 10 --max-parallel 5
```

| Аргумент | По умолчанию | Описание |
|----------|-------------|----------|
| `--domains` | из конфига | Список доменов через пробел |
| `--proxy` | из `CENSOR_CHECK_PROXY_URL` | URL прокси (пусто = прямое соединение) |
| `--timeout` | из `CENSOR_CHECK_TIMEOUT` | Таймаут на домен (секунды) |
| `--max-parallel` | из `CENSOR_CHECK_MAX_PARALLEL` | Макс. параллельных проверок |

## Configuration

Все настройки загружаются из `.env` файла.

### API & Connection

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `CHECKER_API_URL` | `https://xray-checker.kutovoy.dev` | URL Xray Checker API |
| `CHECKER_API_USERNAME` | | Basic auth username (для полной диагностики с адресами серверов) |
| `CHECKER_API_PASSWORD` | | Basic auth password |

### Timeouts & Checks

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `DNS_TIMEOUT` | `5` | Таймаут DNS-разрешения (секунды) |
| `TCP_TIMEOUT` | `5` | Таймаут TCP-соединения (секунды) |
| `RKN_CHECK_ENABLED` | `true` | Включить проверку блокировок RKN |
| `RKN_API_URL` | `https://rknweb.ru/api` | URL API для RKN-проверок |
| `RKN_THROTTLE_CHECK_ENABLED` | `true` | Включить обнаружение DPI-троттлинга (16–20 КБ) |
| `TUNNEL_TEST_ENABLED` | `true` | Включить legacy tunnel-тесты прокси |
| `TUNNEL_TEST_URL` | `https://httpbin.org/ip` | URL для tunnel-теста |
| `PROXY_SNI_TEST_ENABLED` | `true` | Включить SNI-тест через прокси |
| `PROXY_SNI_DOMAIN` | `max.ru` | Домен для SNI-теста |
| `PROXY_STATUS_CHECK_URL` | `http://cp.cloudflare.com/generate_204` | URL для проверки TCP-туннеля |
| `PROXY_IP_CHECK_URL` | `https://api.ipify.org?format=text` | URL для определения exit IP |

### Xray Core (VLESS/Trojan/Shadowsocks)

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `XRAY_TEST_ENABLED` | `true` | Включить тестирование через Xray core |
| `XRAY_BINARY_PATH` | `xray` | Путь к бинарнику Xray (автозагрузка если не найден) |
| `SUBSCRIPTION_URL` | | URL подписки с VLESS/Trojan/SS share-ссылками |
| `SUBSCRIPTION_HWID` | | HWID-заголовок для запроса подписки (x-hwid) |

### Analysis Scope

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `ANALYZE_ONLINE_PROXIES` | `false` | Анализировать только offline-прокси (false) или все |
| `CHECK_INTERVAL_SECONDS` | `300` | Интервал для `--watch` режима (секунды, минимум 60) |
| `CHECK_HOST_API_KEY` | | API-ключ для Check-Host.net |

### Notifications

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `NOTIFY_TELEGRAM_ENABLED` | `false` | Включить Telegram-уведомления |
| `TELEGRAM_BOT_TOKEN` | | Токен Telegram-бота |
| `TELEGRAM_CHAT_ID` | | Chat ID для уведомлений |

### Censor-Check

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `CENSOR_CHECK_DOMAINS` | | Домены через запятую (пусто = встроенный список ~30 сайтов) |
| `CENSOR_CHECK_TIMEOUT` | `4` | Таймаут на домен (секунды) |
| `CENSOR_CHECK_MAX_PARALLEL` | `10` | Макс. параллельных проверок |
| `CENSOR_CHECK_PROXY_URL` | | Прокси для censor-check (пусто = прямое соединение) |

### Logging

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `LOG_LEVEL` | `INFO` | Уровень логирования |
| `LOG_FILE` | `xray-analyzer.log` | Путь к файлу лога |

## Docker

```bash
docker compose up -d
docker compose logs -f xray-analyzer
docker compose logs -f xray-checker
```

## Project Structure

```
src/xray_analyzer/
├── core/
│   ├── config.py              # Settings management
│   ├── logger.py              # Structured logging
│   ├── models.py              # Data models
│   ├── analyzer.py            # Main orchestrator
│   └── xray_client.py         # Xray Checker API client
├── diagnostics/
│   ├── dns_checker.py         # DNS resolution + Check-Host comparison
│   ├── tcp_checker.py         # TCP connection tests
│   ├── tcp_ping_checker.py    # TCP ping / latency
│   ├── rkn_checker.py         # RKN blocking checks
│   ├── proxy_tcp_checker.py   # Proxy TCP tunnel
│   ├── proxy_ip_checker.py    # Proxy exit IP
│   ├── proxy_sni_checker.py   # Proxy SNI check
│   ├── tunnel_checker.py      # Legacy proxy tunnel
│   ├── proxy_cross_checker.py # Cross-proxy connectivity tests
│   ├── proxy_rkn_throttle_checker.py  # DPI throttle detection
│   ├── proxy_xray_checker.py  # VLESS/Trojan/SS via Xray
│   ├── xray_manager.py        # Xray process management
│   ├── xray_downloader.py     # Xray binary auto-download
│   ├── censor_checker.py      # Censorship / domain blocking check
│   └── subscription_parser.py # Subscription URL parser
├── notifiers/
│   ├── base.py                # Notifier interface
│   ├── telegram.py            # Telegram notifications
│   └── manager.py             # Notifier coordinator
└── cli.py                     # CLI entry point
```
