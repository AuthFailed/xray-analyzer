# Архитектура

## Поток данных

```
                 ┌──────────────────────┐
                 │ CLI (argparse)       │ cli.py / cli_dpi.py
                 └──────────┬───────────┘
                            │
              ┌─────────────▼──────────────┐
              │ analyze_subscription_      │ core/standalone_analyzer.py
              │   proxies (оркестратор)    │
              └──┬─────────────────────┬───┘
                 │                     │
        парсит   │                     │ гоняет per-proxy конвейер
   share-ссылки  │                     │ через asyncio.gather
                 │                     │
       ┌─────────▼─────┐ ┌───────────┐ │
       │ Subscription  │ │ Xray      │ │
       │ parser        │ │ binary    │ │
       └───────────────┘ └───────────┘ │
                                       │
        ┌──────────────────────────────▼──────────────────────┐
        │                   diagnostics/                       │
        │                                                      │
        │  DNS  ─ TCP ─ Ping ─ RKN ─ Xray/Proxy ─ Cross ─ DPI │
        └───────────────────────┬──────────────────────────────┘
                                │ DiagnosticResult[]
                    ┌───────────▼────────────┐
                    │  recommendation_engine │
                    └───────────┬────────────┘
                                │ HostDiagnostic[]
                    ┌───────────▼────────────┐
                    │  NotifierManager       │  notifiers/
                    │   → telegram и т.д.    │
                    └────────────────────────┘
```

## Конвейер проверок на прокси

`core/standalone_analyzer.py::analyze_subscription_proxies` последовательно для каждого прокси:

1. **DNS-резолюция** со сравнением с Check-Host.net — `dns_checker.py`
2. **TCP-соединение** — `tcp_checker.py`
3. **TCP-ping** — `tcp_ping_checker.py`
4. **RKN-блоклист** через API `rknweb.ru` — `rkn_checker.py`
5. **Для VLESS/Trojan/SS** (если задан `SUBSCRIPTION_URL`): запускается `XrayInstance`, проверяется связность — `proxy_xray_checker.py`, `xray_manager.py`
6. **Для HTTP/SOCKS**: TCP-туннель, exit IP, SNI, legacy-туннель — `proxy_tcp_checker.py`, `proxy_ip_checker.py`, `proxy_sni_checker.py`, `tunnel_checker.py`

После прохода по всем прокси оркестратор запускает два глобальных прохода:

- **Cross-proxy ретест** — каждый проблемный хост ретраится через рабочий прокси, чтобы отделить локальные сетевые проблемы от серверных (`proxy_cross_checker.py`).
- **RKN DPI throttle** — обнаружение обрыва 16–20 КБ прямым подключением и через рабочий прокси (`proxy_rkn_throttle_checker.py`, `core/throttle_checker_runner.py`).

## Стек DPI-проб

Подкоманды `xray-analyzer dpi ...` адаптированы из [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT). Каждая проба прогоняет обработку исключений через `error_classifier.classify()`, который обходит цепочку исключений и эмитит стабильную `ErrorLabel` — `TLS_DPI`, `TCP_16_20`, `ISP_PAGE` и т. д. (см. [output.md#таксономия-ошибок-dpi](output.md#таксономия-ошибок-dpi)).

| Модуль | Роль |
|--------|------|
| `dns_dpi_prober.py` | UDP (9 резолверов) vs DoH JSON (7 резолверов); сборка stub-IP, встречающихся ≥2× |
| `tls_version_probe.py` | Форсированные TLS 1.2 / 1.3 пробы |
| `http_injection_probe.py` | Детекция HTTP-инъекций на порту 80; делит `evaluate_response` с TLS-пробой для ловли ISP-заглушек / HTTP-451 / кросс-доменных редиректов |
| `fat_probe_checker.py` | Keepalive-сокет + 16 HEAD с 4 КБ `X-Pad`; обрыв в окне 1–30 КБ → `TCP_16_20`. Поддерживает IP+SNI override через кастомный `aiohttp.AbstractResolver` |
| `cdn_target_scanner.py` | Массовый fat-probe по `data/tcp16_targets.json`, группировка по ASN / провайдеру |
| `sni_brute_force_checker.py` | Перебор `data/whitelist_sni.txt` с `hint_rtt_ms` для поиска рабочего SNI под заблокированный CDN-IP |
| `telegram_checker.py` | Параллельные 30 МБ DL + 10 МБ UL + TCP-ping всех 5 DC |

Встроенные данные в `src/xray_analyzer/data/`:

- `dns_servers.json` — список UDP + DoH резолверов
- `tcp16_targets.json` — CDN/хостинг-IP, сгруппированные по ASN
- `whitelist_sni.txt` — кандидаты SNI для брут-форса

Атрибуция источников — `data/CREDITS.md`.

## Сервер метрик

`metrics/server.py` — крошечный aiohttp-сервер, отдающий `/metrics` (Prometheus text format v0.0.4) и `/health`. Пишет формат вручную — без зависимости от `prometheus-client`; состояние — in-memory `MetricsState`, мутирующийся в том же event loop, что и сканы, поэтому локи не нужны.

В режиме `serve --subscription` каждый прокси попадает в `MetricsState._entries` отдельной записью с уникальным label'ом (имя share-ссылки или `host:port`), так что каждая метрика эмитится по одной на прокси.

## Структура проекта

```
src/xray_analyzer/
├── cli.py                            # argparse entry point, dispatch команд
├── cli_dpi.py                        # группа подкоманд xray-analyzer dpi
├── core/
│   ├── standalone_analyzer.py        # основной оркестратор (analyze_subscription_proxies)
│   ├── config.py                     # Settings singleton (pydantic-settings)
│   ├── cross_proxy_tests.py          # ретест проблемных хостов через рабочий прокси
│   ├── logger.py                     # structlog setup
│   ├── models.py                     # DiagnosticResult / HostDiagnostic / CheckStatus
│   ├── proxy_url.py                  # build_proxy_url и хелперы
│   ├── recommendation_engine.py      # маппинг комбинаций сбоев в человеческие рекомендации
│   └── throttle_checker_runner.py    # батч-пробы 16-20 КБ
├── diagnostics/
│   ├── dns_checker.py                # локальный DNS + кросс-чек с Check-Host.net
│   ├── dns_dpi_prober.py             # UDP vs DoH + сбор stub-IP
│   ├── tcp_checker.py                # TCP connect-тест
│   ├── tcp_ping_checker.py           # TCP-пинг / latency
│   ├── tls_version_probe.py          # форсированные TLS 1.2 / 1.3 пробы
│   ├── http_injection_probe.py       # детекция HTTP-инъекций
│   ├── fat_probe_checker.py          # TCP 16-20 KB fat-probe
│   ├── cdn_target_scanner.py         # массовый fat-probe по CDN/ASN
│   ├── sni_brute_force_checker.py    # SNI-брут по whitelist'у
│   ├── telegram_checker.py           # Telegram DL/UL/DC-ping
│   ├── rkn_checker.py                # блоклист rknweb.ru
│   ├── proxy_tcp_checker.py          # TCP-туннель-проба прокси
│   ├── proxy_ip_checker.py           # exit-IP через прокси
│   ├── proxy_sni_checker.py          # SNI через прокси
│   ├── proxy_cross_checker.py        # cross-proxy доступность
│   ├── proxy_rkn_throttle_checker.py # 16-20 KB через прокси
│   ├── proxy_xray_checker.py         # VLESS/Trojan/SS туннель через Xray
│   ├── xray_manager.py               # lifecycle XrayInstance
│   ├── xray_downloader.py            # автоскачивание бинарника Xray
│   ├── subscription_parser.py        # парсинг vless://, trojan://, ss:// share-URL
│   ├── error_classifier.py           # стабильная классификация исключений → ErrorLabel
│   └── censor_checker.py             # конвейер bulk-скана
├── metrics/
│   └── server.py                     # aiohttp-based /metrics + /health
├── notifiers/
│   ├── base.py                       # Protocol нотифаера
│   ├── telegram.py                   # Telegram-бот
│   └── manager.py                    # fan-out по включённым нотифаерам
└── data/                             # встроенные DNS-резолверы, CDN-таргеты, SNI-whitelist
```
