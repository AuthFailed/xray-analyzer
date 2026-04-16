# Модель вывода

Как читать то, что тулкит печатает, эмитит и экспортирует.

- [Статусы проверок](#статусы-проверок)
- [Сводный статус по хосту](#сводный-статус-по-хосту)
- [Статусы censor-check и типы блокировок](#статусы-censor-check-и-типы-блокировок)
- [Таксономия ошибок DPI](#таксономия-ошибок-dpi)
- [Метрики Prometheus](#метрики-prometheus)
- [Коды выхода](#коды-выхода)

---

## Статусы проверок

Каждый отдельный шаг диагностики эмитит `CheckStatus`:

| Значок | Значение | Смысл |
|--------|----------|-------|
| `✓` | `PASS` | Проверка прошла |
| `⚠` | `WARN` | Некритичная проблема — зафиксирована, но не является блокером (например, локальный DNS не совпал с Check-Host, но путь всё равно рабочий) |
| `✗` | `FAIL` | Жёсткий сбой |
| `⏱` | `TIMEOUT` | Превышен таймаут — для кодов выхода трактуется как `FAIL` |
| `○` | `SKIP` | Намеренно пропущено (обычно из-за более раннего сбоя, делающего шаг избыточным) |

Каждый результат также несёт `CheckSeverity` — `INFO`, `WARNING`, `ERROR` или `CRITICAL`, — именно severity влияет на сводный статус хоста.

## Сводный статус по хосту

`HostDiagnostic.overall_status` вычисляется на основе отдельных статусов + severity:

| Статус | Severity | Влияние на хост |
|--------|----------|-----------------|
| `FAIL` | `CRITICAL` / `ERROR` | Хост → `FAIL` (жёсткий) |
| `FAIL` | `WARNING` / `INFO` | Хост → `WARN` (только если был `PASS`; никогда не понижает `FAIL`) |
| `TIMEOUT` | любая | Хост → `FAIL` |
| `PASS` | любая | Без изменений |
| `SKIP` | любая | Без изменений |

Проще говоря: мягкие сбои (warning/info) лишь понижают ранее зелёный хост до `WARN`. До `FAIL` понижают только жёсткие сбои (`ERROR` / `CRITICAL`) или таймаут.

---

## Статусы censor-check и типы блокировок

`scan` и `serve` возвращают по домену один из трёх вердиктов:

| `DomainStatus` | Смысл |
|----------------|-------|
| `OK` | HTTP или HTTPS вернули 2xx/3xx и следов подмены не обнаружено |
| `BLOCKED` | Что-то на пути не дало запросу дойти до сайта |
| `PARTIAL` | Запрос долетел, но был отклонён (4xx/5xx) или подменён (DPI-сигнал, но контент всё же дошёл) |

Поле `block_type` в `DomainCheckResult` уточняет **почему**:

| `block_type` | Что произошло |
|--------------|---------------|
| `DNS` | Резолвинг имени полностью провалился |
| `DNS-SPOOF` | Резолвер вернул известный RKN-stub (Rostelecom / MTS / Beeline / Megafon) или bogon |
| `IP/TCP` | DNS ок, но TCP 443 + 80 оба закрыты |
| `IP/HTTP` | TCP закрыт, и HTTP-ответа тоже нет |
| `TLS/SSL` | Сертификат TLS не валидируется |
| `HTTP(S)` | HTTP и HTTPS оба вернули 0 байт (reset в середине запроса) |
| `HTTP-RESPONSE` | HTTP и HTTPS вернули 4xx–5xx — сайт досягаем, но отказывает |
| `REGIONAL` | Контент страницы соответствует AI/social-геоблоку (ChatGPT, Grok, Netflix и т. п.) |
| `…/DPI` | Составной — один из типов выше **плюс** хотя бы один сильный DPI-сигнал (подтверждённая SNI-вариантность, инъекция Host-заголовка, fast-RST на 192.0.2.1, DoH-рассинхронизация) |

Сильные DPI-сигналы учитываются в `block_type`; голая keyword-проба остаётся мягким сигналом и сама по себе `block_type` не меняет.

---

## Таксономия ошибок DPI

Каждая DPI-проба классифицирует своё падение через стабильную `ErrorLabel` (см. `src/xray_analyzer/diagnostics/error_classifier.py`). Метка выбирается обходом цепочки `__cause__` / `__context__` и маппингом на:

| Метка | Триггер |
|-------|---------|
| `OK` | успех |
| `DNS_FAIL` | NXDOMAIN, SERVFAIL, `socket.gaierror`, таймаут резолвера |
| `DNS_FAKE` | подозрительный IP (stub, 198.18/15 benchmarking, bogon) |
| `TCP_TIMEOUT` | обычный таймаут TCP/L4 |
| `TCP_REFUSED` | RST во время handshake / `ECONNREFUSED` |
| `TCP_RST` | RST в середине стрима |
| `TCP_ABORT` | `ECONNRESET` / `ECONNABORTED` |
| `NET_UNREACH` | `ENETUNREACH` |
| `HOST_UNREACH` | `EHOSTUNREACH` |
| `POOL_TIMEOUT` | pool-таймаут aiohttp (нет свободного сокета) |
| `TLS_DPI` | TLS-alert / handshake failure, характерный для middle-box |
| `TLS_MITM` | невалидный сертификат (self-signed, unknown CA, expired, hostname mismatch) |
| `TLS_BLOCK` | явный version/cipher protocol alert |
| `TCP_16_20` | обрыв соединения внутри окна 1–30 КБ fat-probe (потолок RU-DPI на шифротекст) |
| `ISP_PAGE` | HTTP 451 / кросс-доменный редирект на известную ISP-заглушку |
| `READ_ERR` | обобщённый разрыв на чтении после установленного соединения |
| `GENERIC` | fallback |

---

## Метрики Prometheus

Публикуются на `GET /metrics` командой `xray-analyzer serve` в текстовом формате Prometheus (v0.0.4).

| Метрика | Тип | Labels | Значение |
|---------|-----|--------|----------|
| `xray_domain_accessible` | gauge | `domain`, `status`, `block_type`, `proxy` | `1` OK, `0.5` PARTIAL, `0` BLOCKED |
| `xray_domain_http_code` | gauge | `domain`, `scheme` (`http` / `https`), `proxy` | Код HTTP, `0` если ответа нет |
| `xray_domain_tls_valid` | gauge | `domain`, `proxy` | `1` валидный сертификат, `0` иначе |
| `xray_domain_dpi_detected` | gauge | `domain`, `proxy` | `1` если сработал хоть один DPI-сигнал |
| `xray_scan_domains_total` | gauge | `proxy` | Количество доменов в последнем скане |
| `xray_scan_domains_ok` | gauge | `proxy` | Счётчик OK |
| `xray_scan_domains_blocked` | gauge | `proxy` | Счётчик BLOCKED |
| `xray_scan_domains_partial` | gauge | `proxy` | Счётчик PARTIAL |
| `xray_scan_last_run_timestamp_seconds` | gauge | `proxy` | Unix-время окончания последнего скана |
| `xray_scan_duration_seconds` | gauge | `proxy` | Длительность последнего скана |
| `xray_scan_up` | gauge | `proxy` | `1` если последний скан прошёл, `0` если упал или не было |

Значения label `proxy`:

- `direct` — если прокси не настроен
- Имя share-ссылки (или `host:port` как fallback) в режиме `serve --subscription`
- Иначе — сырой URL прокси

### Healthcheck

`GET /health`:

- `200 OK` после первого удачного скана
- `503` пока ждёт первого скана
- `500` если первый скан упал

---

## Коды выхода

Все команды следуют Unix-конвенции:

| Код | Когда |
|-----|-------|
| `0` | Успех — все проверки прошли, либо прошёл хотя бы один прокси/домен (зависит от команды) |
| `1` | Сбой — одна или несколько проверок упали, либо команда сама упала |

По командам:

- `analyze` — `0`, если **каждый** хост сводится к `PASS` или `WARN`; любой `FAIL` → `1`.
- `check` — `0`, если у домена `overall_status` ∈ `{PASS, WARN}`.
- `check --subscription` — `0`, если хотя бы один прокси прошёл.
- `scan` — `0`, если ни один домен не `BLOCKED` (`PARTIAL` не валит).
- `serve` — работает бесконечно; `0` по SIGINT, `1` при фатальной ошибке старта.
- `dpi dns` — `0`, только если **все** домены `ok`.
- `dpi tcp16` — `0`, если `label == "ok"`.
- `dpi cdn-scan` — `0`, если общий вердикт `ok`.
- `dpi sni-brute` — `0`, если найден хотя бы один рабочий SNI.
- `dpi telegram` — `0`, только если все этапы (DL, UL, DC-ping) прошли.
