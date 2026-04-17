# Xray Analyzer

[English](README.md) · [Русский](README.ru.md)

Асинхронный диагностический тулкит для Xray-прокси и сетевых маршрутов между вами и открытым интернетом.

Совмещает в одном CLI (`uv run xray-analyzer`) полноценный конвейер проверки прокси, шесть уровней DPI-проб, массовый сканер цензуры и демон метрик для Prometheus.

## Возможности

- **Диагностика парка прокси** — обращается к API [Xray Checker](https://github.com/kutovoy/xray-checker) (или напрямую к URL-подписке) и прогоняет 8–12 целевых проверок для каждого offline-прокси: DNS, TCP, ping, блок-лист RKN, Xray-туннель, exit-IP, SNI, DPI-троттлинг 16–20 КБ.
- **Пошаговая диагностика одного хоста** — `check <domain>` проходит последовательно DNS → TCP → ping → TLS → HTTP → DPI и печатает каждый шаг в реальном времени.
- **Массовый сканер цензуры** — `scan` параллельно проверяет сотни доменов с живым прогресс-баром; встроенный список плюс внешние блок-листы (`whitelist`, `russia-inside`, `russia-outside`, `ukraine-inside`).
- **Глубокие DPI-пробы** — прямой UDP vs DoH DNS, split TLS 1.2/1.3, обнаружение HTTP-инъекций, keepalive fat-probe для TCP-обрыва на 16–20 КБ, массовый скан CDN/ASN, брут-форс SNI, проверка доступности Telegram DC.
- **Экспортер Prometheus** — `serve` гоняет периодические сканы и публикует метрики per-domain / per-proxy на `/metrics`.
- **Docker-first** — один `docker compose up` поднимает checker + analyzer + опциональный Prometheus/Grafana-стек.

Построено на `aiohttp`, `pydantic-settings`, `rich`, `structlog`. Требуется Python 3.14+.

## Быстрый старт

### Docker Compose (рекомендуется)

```bash
cp .env.example .env
# отредактируйте .env — как минимум задайте SUBSCRIPTION_URL
docker compose up -d
docker compose logs -f xray-analyzer
```

Профиль `monitoring` добавляет Prometheus и Grafana:

```bash
docker compose --profile monitoring up -d
# Prometheus → http://localhost:9091
# Grafana    → http://localhost:3000   (admin/admin)
```

### Локально

```bash
git clone https://github.com/AuthFailed/xray-analyzer
cd xray-analyzer
uv sync
uv run xray-analyzer --help
```

При первом запуске тестов VLESS/Trojan/SS бинарник Xray автоматически скачивается, если его нет в `$PATH` или по пути из `XRAY_BINARY_PATH`.

## Первые команды

```bash
uv run xray-analyzer analyze                          # диагностика парка прокси
uv run xray-analyzer check meduza.io                  # пошаговая проверка домена
uv run xray-analyzer scan --list whitelist            # массовый скан цензуры
uv run xray-analyzer serve --port 9090                # демон с /metrics
uv run xray-analyzer dpi tcp16 5.161.249.234          # DPI fat-probe 16-20 КБ
```

## Документация

- **[Справочник CLI](docs/ru/cli.md)** — все команды, все флаги, примеры вывода
- **[Конфигурация](docs/ru/configuration.md)** — все переменные окружения
- **[Модель вывода](docs/ru/output.md)** — статусы, типы блокировок, DPI-метки ошибок, метрики Prometheus, коды выхода
- **[Архитектура](docs/ru/architecture.md)** — поток данных, карта модулей, standalone-режим и режим checker-API
- **[Разработка](docs/ru/development.md)** — как запускать тесты, линтер, type-checker, как контрибьютить

## Лицензия

MIT.

## Благодарности

- Пробы Tier 1–6 адаптированы из [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT).
- Логика `scan` повторяет эвристики bash-скрипта [@tracerlab](https://t.me/tracerlab).
- Встроенные списки доменов — см. [`src/xray_analyzer/data/CREDITS.md`](src/xray_analyzer/data/CREDITS.md).
- API Xray Checker предоставлен проектом [kutovoy/xray-checker](https://github.com/kutovoy/xray-checker).
