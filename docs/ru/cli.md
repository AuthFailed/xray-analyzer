# Справочник CLI

Каждая команда асинхронна, выводит стилизованный вывод через Rich и возвращает код `0` при успехе / `1` при сбое или обнаружении блокировок.

**Команды:**

- [`analyze`](#analyze) — диагностика парка прокси из API checker'а или URL-подписки
- [`check`](#check) — пошаговая диагностика одного домена
- [`scan`](#scan) — массовый скан цензуры по множеству доменов
- [`serve`](#serve) — периодический `scan` + endpoint `/metrics` для Prometheus
- [`status`](#status) — здоровье настроенного Xray Checker API
- [`dpi dns`](#dpi-dns) — сравнение прямой UDP-резолюции с DoH
- [`dpi tcp16`](#dpi-tcp16) — одиночная fat-probe для TCP-обрыва 16–20 КБ
- [`dpi cdn-scan`](#dpi-cdn-scan) — массовый fat-probe по ASN / провайдерам
- [`dpi sni-brute`](#dpi-sni-brute) — брут-форс SNI по whitelist'у для заблокированного IP
- [`dpi telegram`](#dpi-telegram) — проверка Telegram: DL / UL / DC

---

## `analyze`

Полный конвейер по каждому прокси, возвращённому Xray Checker API, либо по каждой share-ссылке из подписки в *standalone*-режиме (без API checker'а — только `SUBSCRIPTION_URL`).

```bash
uv run xray-analyzer analyze
uv run xray-analyzer analyze --watch
uv run xray-analyzer analyze --subscription-url https://example/sub --no-xray
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `--watch` | off | Бесконечный цикл с интервалом `CHECK_INTERVAL_SECONDS` (мин. 60 с) |
| `--subscription-url <URL>` | env | Переопределяет `SUBSCRIPTION_URL` |
| `--subscription-hwid <HWID>` | env | Заголовок `x-hwid` для запроса подписки |
| `--checker-api-url <URL>` | env | Переопределяет `CHECKER_API_URL` |
| `--checker-api-username / --checker-api-password` | env | Basic auth для checker'а |
| `--analyze-online` | off | Проверять в том числе прокси, которые checker считает online |
| `--no-xray` | off | Пропустить тест VLESS/Trojan/SS-туннеля |
| `--no-rkn-throttle` | off | Пропустить пробу 16–20 КБ |
| `--no-sni` | off | Пропустить SNI-тест через прокси |
| `--check-host-api-key <KEY>` | env | API-ключ Check-Host.net для сравнения DNS |
| `--proxy-status-url / --proxy-ip-url / --sni-domain` | env | Переопределяют URL-ы туннель-тестов |
| `--interval <SECONDS>` | env | Переопределяет `CHECK_INTERVAL_SECONDS` для `--watch` |

### Конвейер на каждый прокси

1. **DNS** — локальный резолвер сравнивается с пробами Check-Host.net из разных стран.
2. **TCP connection** — порт 443 открывается.
3. **TCP ping** — замер RTT.
4. **RKN blocklist** — API `rknweb.ru`.
5. **Proxy tunnel** — для VLESS/Trojan/SS: запускается `XrayInstance`, проверяется туннель и exit IP. Для HTTP/SOCKS: TCP-туннель, exit IP, SNI, legacy HTTP-туннель.
6. **Cross-proxy retest** — любой проблемный хост ретраится через рабочий прокси, чтобы отделить локальные проблемы от серверных.
7. **RKN DPI throttle** — обнаружение обрыва в 16–20 КБ (прямое подключение и через рабочий прокси).

### Вывод

```
╭─ Analysis Result ───────────────────────────────────────╮
│ Total hosts: 14  |  ✓ OK: 11  |  ⚠ WARN: 1  |  ✗ PROBLEMS: 2 │
╰─────────────────────────────────────────────────────────╯

⚠ HOSTS WITH PROBLEMS
  → nl-ams-1.example.net
  ────────────────────────────────────────────────────
    ✗ FAIL  RKN Throttle
       Connection dropped at ~18 KB (DPI signature)
       Received: 17408 bytes (17.0 KB)
    What to do:
      → Change obfuscation (REALITY → XTLS-Vision) or rotate the server IP

✓ HOSTS WITHOUT ISSUES
  Host               DNS   TCP   Ping  RKN Thr  Proxy
  de-fra-2.example   ✓     ✓     ✓     ✓        ✓
  …
```

Колонки компактной таблицы:

- **DNS** — локальный резолвер согласен с Check-Host.net (DNS не подменяется).
- **TCP / Ping** — порт 443 открыт, latency измерим.
- **RKN Thr** — обрыв на 16–20 КБ не обнаружен.
- **Proxy** — Xray-туннель (VLESS/Trojan/SS) или HTTP/SOCKS-туннель прошли проверку.

---

## `check`

Пошагово прогоняет один хост по полному конвейеру цензур-диагностики, в реальном времени. Подходит для вопроса «почему именно этот домен не открывается?».

```bash
uv run xray-analyzer check meduza.io
uv run xray-analyzer check meduza.io --port 8443
uv run xray-analyzer check meduza.io --proxy socks5://127.0.0.1:1080
uv run xray-analyzer check meduza.io --proxy 'vless://...@host:443?...'
uv run xray-analyzer check meduza.io --subscription https://example/sub
```

| Аргумент | По умолчанию | Описание |
|----------|--------------|----------|
| `host` | required | Домен или IP |
| `--port <N>` | `443` | Порт для TCP/TLS |
| `--proxy <URL>` | env | HTTP/SOCKS-URL или share-ссылка VLESS/Trojan/SS (последняя автоматически запускается через Xray на `socks5://127.0.0.1:<auto>`) |
| `--timeout <SECONDS>` | env | Переопределение таймаута на шаг |
| `--subscription <URL>` | — | Проверить домен через **каждый** VLESS/Trojan/SS из подписки (до 8 параллельных Xray-инстансов); в конце — таблица результатов по прокси |

### Вывод — одиночный прокси

```
╭─ Diagnosing: meduza.io ─────────────────────────────────╮
│ Direct connection (no proxy)                            │
╰─────────────────────────────────────────────────────────╯

  ✓ DNS             3 IPs resolved, 3 match Check-Host                 120ms
  ✓ TCP             443 open                                            24ms
  ✓ Ping            avg 22 ms, 0% loss                                  96ms
  ✗ TLS             handshake alert (TLS_DPI)                          280ms
  ○ HTTP            skipped after TLS failure
  ○ DPI             skipped after TLS failure

╭ meduza.io ──────────────────────────────────────────────╮
│ ✗  FAIL                                                 │
╰─────────────────────────────────────────────────────────╯

Recommendations:
  → The path is being DPI-blocked on TLS — try REALITY or a different SNI
```

Каждый шаг помечен одним из значков из [output.md#статусы-проверок](output.md#статусы-проверок). `SKIP` означает, что шаг был намеренно пропущен — как правило, из-за предыдущего критического сбоя.

### Вывод — режим `--subscription`

По одной строке на прокси во время выполнения, а в конце — сводная таблица:

```
  ✓ de-fra-01
  ✗ nl-ams-02
  ✓ de-ber-03
  …

Proxy         Status
de-fra-01     ✓ pass
nl-ams-02     ✗ fail
de-ber-03     ✓ pass

8 passed, 2 failed out of 10 proxies
```

Код выхода `0`, если хотя бы один прокси прошёл.

---

## `scan`

Параллельный скан цензуры по множеству доменов. DNS + детекция RKN-stub, TCP на 443/80, валидация TLS-сертификата, коды HTTP/HTTPS-запросов и набор DPI-сигналов (SNI-вариантность, инъекция Host-заголовка, fast-RST, DoH-рассинхронизация).

```bash
uv run xray-analyzer scan                                    # встроенный ~30-доменный список
uv run xray-analyzer scan google.com youtube.com             # явный список
uv run xray-analyzer scan --list whitelist                   # whitelist мобильного интернета РФ
uv run xray-analyzer scan --list russia-inside               # itdoginfo/allow-domains
uv run xray-analyzer scan --file ./domains.txt
uv run xray-analyzer scan --proxy socks5://127.0.0.1:1080 --max-parallel 20
```

| Аргумент | По умолчанию | Описание |
|----------|--------------|----------|
| `domains` (позиционный) | — | Явный список (перекрывает `--list` / `--file` / конфиг) |
| `--list <name>` | `default` | `default` / `whitelist` / `russia-inside` / `russia-outside` / `ukraine-inside` |
| `--file <PATH>` | — | Текстовый файл: один домен в строке (разрешены комментарии `#`, невалидные строки подсвечиваются) |
| `--proxy <URL>` | env | URL HTTP/SOCKS или share-ссылка Xray |
| `--timeout <SECONDS>` | `4` | Таймаут на домен |
| `--max-parallel <N>` | `10` | Максимум параллельных проверок |

Код выхода `1`, если хотя бы один домен помечен `BLOCKED`.

### Вывод

```
╭─ 🌐  Censorship Scan ───────────────────────────────────╮
│ Via proxy: socks5://127.0.0.1:1080                      │
╰─────────────────────────────────────────────────────────╯

  ✓ youtube.com               OK       TLS✓  HTTPS 200
  ✗ rutracker.org             BLOCKED (DNS-SPOOF)  stub:195.208.4.1
  ⚠ chatgpt.com               PARTIAL (REGIONAL)   TLS✓  HTTPS 403
  …

╭─ Censor-Check — Summary ───────────────────────────────╮
│ ✗  30 domains checked  ·  ✓ 24 OK  ·  ✗ 4 blocked  ·  ⚠ 2 partial  ·  12.4s │
│ via socks5://127.0.0.1:1080                             │
╰─────────────────────────────────────────────────────────╯

✗  Blocked (4)
  Domain               Reason        Details
  rutracker.org        DNS-SPOOF     195.208.4.1  stub:195.208.4.1
  …
```

Расшифровка `block_type` — см. [output.md#статусы-censor-check-и-типы-блокировок](output.md#статусы-censor-check-и-типы-блокировок).

---

## `serve`

Запускает `scan` по расписанию и публикует метрики Prometheus.

```bash
uv run xray-analyzer serve
uv run xray-analyzer serve --port 9100 --interval 120
uv run xray-analyzer serve --list whitelist --proxy socks5://127.0.0.1:1080
uv run xray-analyzer serve --subscription https://example/sub
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `--port <N>` | `9090` (env `METRICS_PORT`) | Порт |
| `--host <IP>` | `0.0.0.0` (env `METRICS_HOST`) | Bind-адрес |
| `--interval <SECONDS>` | `CHECK_INTERVAL_SECONDS` | Интервал между сканами |
| `domains` / `--list` / `--file` | как в `scan` | Набор целевых доменов |
| `--proxy <URL>` | env | Единый прокси для всех сканов |
| `--subscription <URL>` | — | Сканировать через **каждый** VLESS/Trojan/SS из подписки; каждый прокси получает свой label во всех метриках |
| `--timeout` / `--max-parallel` | env | Лимиты на домен |

### Endpoints

- `GET /metrics` — текстовый формат Prometheus v0.0.4 — см. [output.md#метрики-prometheus](output.md#метрики-prometheus).
- `GET /health` — `200` после первого успешного скана, `503` пока ждёт первого скана, `500` если первый скан упал.

### Вывод

```
╭─ Metrics server ────────────────────────────────────────╮
│ http://0.0.0.0:9090/metrics                             │
│ 30 domains · scan every 300s · direct connection        │
╰─────────────────────────────────────────────────────────╯

✓ Listening on http://0.0.0.0:9090/metrics  (Ctrl+C to stop)

14:03:11  scan done  ✓ 24 OK · ✗ 4 blocked · ⚠ 2 partial  11.2s · next in 300s
14:08:22  scan done  ✓ 24 OK · ✗ 4 blocked · ⚠ 2 partial  10.9s · next in 300s
…
```

В режиме `--subscription` на каждый цикл печатается по одной строке прогресса на прокси.

---

## `status`

Быстрая проверка здоровья настроенного Xray Checker API.

```bash
uv run xray-analyzer status
```

### Вывод

```
Health: OK

System Information:
  Version: 2.4.1
  Instance: xray-checker
  Uptime: 3d 7h 22m

Proxy Status Summary:
  Total: 14
  Online: 11
  Offline: 3
  Avg Latency: 187ms

Server IP: 203.0.113.17
```

---

## `dpi dns`

Сравнивает прямой UDP/53 с DoH JSON; отлавливает «stub IP», встречающиеся ≥2× в UDP-ответах (типично для ISP-заглушек).

```bash
uv run xray-analyzer dpi dns meduza.io youtube.com
uv run xray-analyzer dpi dns meduza.io --udp-only
uv run xray-analyzer dpi dns meduza.io --doh-only --timeout 8
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `domains` (nargs+) | required | Список доменов |
| `--timeout <SECONDS>` | `5.0` | Таймаут на запрос |
| `--udp-only` / `--doh-only` | — | Отключить одну из сторон сравнения |

### Вывод

```
DNS integrity probe — 2 domain(s)
  UDP: 8.8.8.8 (Google)
  DoH: https://cloudflare-dns.com/dns-query (Cloudflare)
  Stub IPs harvested: 195.208.4.1

Domain        Verdict   UDP answer    DoH answer
meduza.io     spoof     195.208.4.1   95.213.4.17
youtube.com   ok        142.250.x.x   142.250.x.x
```

### Вердикты

- `ok` — UDP и DoH совпадают.
- `spoof` — UDP возвращает иной набор IP, включающий stub/bogon.
- `intercept` — UDP в таймаут, DoH работает (UDP/53 заблокирован на пути).
- `fake_nxdomain` / `fake_empty` — UDP отвечает NXDOMAIN / пусто, DoH работает.
- `doh_blocked` — DoH падает, UDP работает.
- `all_dead` — ни один резолвер не ответил.

Код выхода `0`, только если все домены `ok`.

---

## `dpi tcp16`

Разовая fat-probe против конкретной пары IP/SNI, ищем сигнатуру TCP-обрыва на 16–20 КБ.

```bash
uv run xray-analyzer dpi tcp16 5.161.249.234
uv run xray-analyzer dpi tcp16 5.161.249.234 --sni example.com --iterations 20
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `target` | required | IP или hostname |
| `--port <N>` | `443` | TCP-порт |
| `--sni <name>` | — | Форсить SNI ≠ target (TLS приходит на IP `target`, но анонсирует этот hostname) |
| `--iterations <N>` | `16` | Количество HEAD-запросов с растущим `X-Pad` (каждый добавляет ~4 КБ шифротекста) |

### Как это работает

Открывает одну aiohttp-сессию с `TCPConnector(limit=1, force_close=False)`, чтобы все HEAD переиспользовали один и тот же TCP-сокет. Итерация 0 — чистый HEAD (замер liveness + RTT). Итерации 1..N-1 добавляют накопительные 4 КБ `X-Pad`. Обрывы обычно случаются между 4-й и 5-й итерациями (~16–20 КБ).

### Вывод

```
Fat-probe 5.161.249.234:443 (SNI=example.com)
PASS TCP 16-20 KB Fat Probe: all 16 iterations succeeded (~64 KB ciphertext)
```

либо

```
FAIL TCP 16-20 KB Fat Probe: drop at ≈16 KB (TCP_16_20)
```

Поле `label` в `details` — одна из [DPI-меток ошибок](output.md#таксономия-ошибок-dpi). `TCP_16_20` — именно та сигнатура, которую мы ищем.

---

## `dpi cdn-scan`

Массовая fat-probe по встроенному списку CDN/хостинг-IP (`src/xray_analyzer/data/tcp16_targets.json`), сгруппированная по ASN и провайдеру.

```bash
uv run xray-analyzer dpi cdn-scan
uv run xray-analyzer dpi cdn-scan --max-parallel 20 --limit 50
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `--max-parallel <N>` | `10` | Параллельность fat-probe |
| `--limit <N>` | `0` (все) | Только первые N таргетов |

### Вывод

```
CDN scan — 84 targets, parallelism 20
Provider     ASN       OK / Total   Blocked   Verdict
Cloudflare   AS13335   12/12        0         ok
Hetzner      AS24940   4/8          4         partial
Rostelecom   AS12389   0/6          6         blocked
…
Overall: partial
```

Вердикт на бакет: `ok` (без обрывов), `partial` (часть обрывается), `blocked` (все таргеты обрываются). Используйте, чтобы выбрать непроблемного провайдера до разворачивания нового прокси.

---

## `dpi sni-brute`

Перебирает большой whitelist доменов, ища такой SNI, который проходит DPI на целевом IP — полезно для настройки REALITY / SNI-маскарада.

```bash
uv run xray-analyzer dpi sni-brute 5.161.249.234 --max 50
uv run xray-analyzer dpi sni-brute 5.161.249.234 --early-exit 3
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `target` | required | IP или hostname |
| `--port <N>` | `443` | TCP-порт |
| `--max <N>` | `200` | Максимум кандидатов из `data/whitelist_sni.txt` |
| `--early-exit <N>` | `1` | Остановиться, найдя столько рабочих SNI |

### Вывод

```
SNI brute-force against 5.161.249.234:443 (cap=50)
PASS SNI Brute-force: found 1 working SNI
Working SNIs:
  • cdn.jsdelivr.net
```

Код выхода `0`, если найден хотя бы один рабочий SNI.

---

## `dpi telegram`

Проверка доступности Telegram — скачивание 30 МБ, загрузка 10 МБ, TCP-пинг всех DC.

```bash
uv run xray-analyzer dpi telegram
uv run xray-analyzer dpi telegram --via-proxy socks5://127.0.0.1:1080
uv run xray-analyzer dpi telegram --total-timeout 120
```

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `--via-proxy <URL>` | — | Весь Telegram-трафик через этот прокси |
| `--total-timeout <SECONDS>` | `60` | Потолок общей длительности пробы |

### Вывод

```
Telegram reachability probe — DL + UL + DC ping (~30 MB download)
PASS Telegram Reachability: all checks green
  Download: PASS, 30.0 MB in 4.8s
  Upload:   PASS, 10.0 MB in 2.1s
  DCs reachable: 5/5
```

Код выхода `0`, только если все три этапа прошли.
