# Конфигурация

Все настройки берутся из файла `.env` (загружается через `pydantic-settings`) или из реальных переменных окружения. У каждого параметра есть разумный default — фактически обязательно задать только `SUBSCRIPTION_URL`, и то лишь при использовании Xray-туннелей.

Шаблон — см. [`.env.example`](../../.env.example).

## API и авторизация

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `CHECKER_API_URL` | `https://xray-checker.kutovoy.dev` | Базовый URL Xray Checker API |
| `CHECKER_API_USERNAME` | — | Basic auth username (даёт доступ к полным эндпоинтам с адресами серверов) |
| `CHECKER_API_PASSWORD` | — | Basic auth password |
| `SUBSCRIPTION_URL` | — | URL-ы подписок с share-ссылками VLESS/Trojan/SS, через запятую |
| `SUBSCRIPTION_HWID` | — | Заголовок `x-hwid` при запросе подписки |

## Таймауты и переключатели проверок

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `DNS_TIMEOUT` | `5` | Секунд на DNS-запрос |
| `TCP_TIMEOUT` | `5` | Секунд на TCP-connect |
| `TUNNEL_TEST_ENABLED` | `true` | Включить legacy HTTP-туннель-тест для HTTP/SOCKS-прокси |
| `TUNNEL_TEST_URL` | `https://httpbin.org/ip` | URL для туннель-теста |
| `PROXY_STATUS_CHECK_URL` | `http://cp.cloudflare.com/generate_204` | URL TCP-туннель-пробы |
| `PROXY_IP_CHECK_URL` | `https://api.ipify.org?format=text` | URL проверки exit-IP |
| `PROXY_SNI_TEST_ENABLED` | `true` | Запускать SNI-тест через прокси |
| `PROXY_SNI_DOMAIN` | `max.ru` | Домен для SNI-теста |
| `RKN_THROTTLE_CHECK_ENABLED` | `true` | Проба 16–20 КБ в `analyze` |
| `RKN_THROTTLE_CONCURRENCY` | `10` | Максимум параллельных RKN-проб |
| `CHECK_HOST_API_KEY` | — | Опциональный ключ Check-Host.net |
| `CHECK_INTERVAL_SECONDS` | `300` | Интервал для `analyze --watch` / `serve` (мин. `60`) |
| `ANALYZE_ONLINE_PROXIES` | `false` | `false` → перепроверять только offline-прокси |

## Xray core

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `XRAY_TEST_ENABLED` | `true` | Включить тестирование VLESS/Trojan/SS-туннелей |
| `XRAY_BINARY_PATH` | `xray` | Путь к `xray` (или `xray` в `$PATH`); при отсутствии — автоскачивание с GitHub releases |

## Scan и serve

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `CENSOR_CHECK_DOMAINS` | — | Список доменов через запятую, заменяющий дефолтный |
| `CENSOR_CHECK_TIMEOUT` | `4` | Таймаут на домен |
| `CENSOR_CHECK_MAX_PARALLEL` | `10` | Максимум параллельных проверок |
| `CENSOR_CHECK_PROXY_URL` | — | Прокси для `scan` / `serve` (пусто → прямое подключение) |
| `METRICS_HOST` | `0.0.0.0` | Bind-хост `serve` |
| `METRICS_PORT` | `9090` | Bind-порт `serve` |

## DPI-пробы

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `DNS_DPI_ENABLED` | `true` | Шаг DNS DPI-проба |
| `DNS_DPI_TIMEOUT` | `5.0` | Таймаут на запрос (секунды) |
| `DPI_TLS_VERSION_SPLIT_ENABLED` | `false` | Split-TLS 1.2/1.3 внутри censor-pipeline |
| `FAT_PROBE_ENABLED` | `false` | Fat-probe внутри censor-pipeline |
| `FAT_PROBE_MIN_KB` / `FAT_PROBE_MAX_KB` | `1` / `30` | Границы окна обрыва |
| `FAT_PROBE_ITERATIONS` | `16` | Количество HEAD-итераций |
| `FAT_PROBE_CHUNK_SIZE` | `4000` | Размер `X-Pad` на итерацию (байт) |
| `FAT_PROBE_CONNECT_TIMEOUT` / `FAT_PROBE_READ_TIMEOUT` | `8.0` / `12.0` | Секунды |
| `FAT_PROBE_DEFAULT_SNI` | `example.com` | Fallback-SNI для `dpi cdn-scan` |
| `SNI_BRUTE_MAX_CANDIDATES` | `200` | Лимит кандидатов для `dpi sni-brute` |
| `TELEGRAM_CHECK_ENABLED` | `false` | Включить Telegram-пробу в censor-pipeline |
| `TELEGRAM_STALL_TIMEOUT` | `10.0` | Таймаут read-stall (секунды) |
| `TELEGRAM_TOTAL_TIMEOUT` | `60.0` | Потолок длительности Telegram-пробы |

## DPI-пробы внутри `serve`

Переключатели для второго периодического цикла, который крутится рядом с доменным сканом и пушит метрики `xray_dpi_*`. По умолчанию всё выключено — `serve` остаётся чистым доменным сканером, пока не включишь явно.

| Переменная | Дефолт | Описание |
|------------|--------|----------|
| `SERVE_DPI_ENABLED` | `false` | Мастер-тумблер — пока `false`, DPI-цикл не стартует, даже если флажки ниже `true` |
| `SERVE_DPI_INTERVAL_SECONDS` | `1800` | Период между итерациями DPI-проб (общий для DNS/CDN/Telegram). Обычный доменный скан использует `CHECK_INTERVAL_SECONDS`, дефолт `300` |
| `SERVE_DPI_DNS_ENABLED` | `false` | Запускать `probe_dns_integrity` каждую итерацию |
| `SERVE_DPI_DNS_DOMAINS` | — | Список доменов через запятую. **Пусто ⇒ DNS-проба пропускается даже при включённом флаге** |
| `SERVE_DPI_CDN_ENABLED` | `false` | Запускать `scan_targets` по встроенному `tcp16_targets.json` |
| `SERVE_DPI_CDN_MAX_PARALLEL` | `10` | Параллельность CDN-скана |
| `SERVE_DPI_CDN_LIMIT` | `0` | Ограничение числа таргетов (`0` = все) |
| `SERVE_DPI_TELEGRAM_ENABLED` | `false` | Запускать `check_telegram` (30 MB DL, 10 MB UL, TCP-ping 5 DC) |

Параметры fat-probe (`FAT_PROBE_*`) и Telegram-таймауты (`TELEGRAM_STALL_TIMEOUT` / `TELEGRAM_TOTAL_TIMEOUT`) общие с CLI `xray-analyzer dpi`.

## Логирование и уведомления

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `LOG_FILE` | `xray-analyzer.log` | Путь к файлу structured-логов |
| `NOTIFY_TELEGRAM_ENABLED` | `false` | Отправлять проблемные отчёты в Telegram |
| `TELEGRAM_BOT_TOKEN` | — | Токен бота |
| `TELEGRAM_CHAT_ID` | — | Chat ID получателя |

## Переменные docker-compose

Эти переменные влияют только на `docker-compose.yml`; сам analyzer их игнорирует.

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `CHECKER_EXTERNAL_PORT` | `2112` | Порт хоста для Xray Checker |
| `METRICS_EXTERNAL_PORT` | `9090` | Порт хоста для `/metrics` |
| `PROMETHEUS_EXTERNAL_PORT` | `9091` | Порт хоста для Prometheus (`--profile monitoring`) |
| `GRAFANA_EXTERNAL_PORT` | `3000` | Порт хоста для Grafana (`--profile monitoring`) |
| `GRAFANA_USER` / `GRAFANA_PASSWORD` | `admin` / `admin` | Креды админа Grafana |
| `METRICS_PROTECTED` | `false` | Basic auth для метрик Xray Checker |
| `METRICS_USERNAME` / `METRICS_PASSWORD` | — | Креды метрик Xray Checker |
| `PROXY_CHECK_INTERVAL` | `300` | Интервал скана Xray Checker |
| `PROXY_CHECK_METHOD` | `ip` | Метод проверки Xray Checker |
| `PROXY_TIMEOUT` | `30` | Таймаут Xray Checker на прокси |
| `CHECKER_LOG_LEVEL` | `info` | Уровень логов Xray Checker |
