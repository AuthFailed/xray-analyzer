# Configuration

All settings come from a `.env` file (loaded by `pydantic-settings`) or real environment variables. Every setting has a sensible default — only `SUBSCRIPTION_URL` is effectively required for anything that spawns Xray.

See [`.env.example`](../../.env.example) for a copy-pasteable template.

## API & auth

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKER_API_URL` | `https://xray-checker.kutovoy.dev` | Xray Checker API base URL |
| `CHECKER_API_USERNAME` | — | Basic auth username (enables full endpoints that expose server addresses) |
| `CHECKER_API_PASSWORD` | — | Basic auth password |
| `SUBSCRIPTION_URL` | — | Comma-separated list of subscription URLs with VLESS/Trojan/SS share links |
| `SUBSCRIPTION_HWID` | — | `x-hwid` header for the subscription request |

## Timeouts & feature toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_TIMEOUT` | `5` | Seconds per DNS query |
| `TCP_TIMEOUT` | `5` | Seconds per TCP connect |
| `TUNNEL_TEST_ENABLED` | `true` | Run the legacy HTTP tunnel test on HTTP/SOCKS proxies |
| `TUNNEL_TEST_URL` | `https://httpbin.org/ip` | Target URL for the tunnel test |
| `PROXY_STATUS_CHECK_URL` | `http://cp.cloudflare.com/generate_204` | TCP-tunnel probe URL |
| `PROXY_IP_CHECK_URL` | `https://api.ipify.org?format=text` | Exit-IP check URL |
| `PROXY_SNI_TEST_ENABLED` | `true` | Run the SNI check through the proxy |
| `PROXY_SNI_DOMAIN` | `max.ru` | Domain used for the SNI test |
| `RKN_THROTTLE_CHECK_ENABLED` | `true` | Run the 16–20 KB probe during `analyze` |
| `RKN_THROTTLE_CONCURRENCY` | `10` | Max parallel RKN throttle probes |
| `CHECK_HOST_API_KEY` | — | Optional key for Check-Host.net |
| `CHECK_INTERVAL_SECONDS` | `300` | Loop interval for `analyze --watch` / `serve` (min `60`) |
| `ANALYZE_ONLINE_PROXIES` | `false` | `false` → only re-check proxies the checker reports as offline |

## Xray core

| Variable | Default | Description |
|----------|---------|-------------|
| `XRAY_TEST_ENABLED` | `true` | Enable VLESS/Trojan/SS tunnel testing |
| `XRAY_BINARY_PATH` | `xray` | Path to `xray` (must be on `$PATH` or absolute); auto-downloaded from GitHub releases if missing |

## Scan & serve

| Variable | Default | Description |
|----------|---------|-------------|
| `CENSOR_CHECK_DOMAINS` | — | Comma-separated override for the default scan list |
| `CENSOR_CHECK_TIMEOUT` | `4` | Per-domain timeout |
| `CENSOR_CHECK_MAX_PARALLEL` | `10` | Max concurrent domain checks |
| `CENSOR_CHECK_PROXY_URL` | — | Proxy for `scan` / `serve` (empty → direct) |
| `METRICS_HOST` | `0.0.0.0` | `serve` bind host |
| `METRICS_PORT` | `9090` | `serve` bind port |

## DPI probes

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_DPI_ENABLED` | `true` | Enable the DNS DPI prober step |
| `DNS_DPI_TIMEOUT` | `5.0` | Per-query timeout (seconds) |
| `DPI_TLS_VERSION_SPLIT_ENABLED` | `false` | Run the TLS 1.2/1.3 split probe inside the censor pipeline |
| `FAT_PROBE_ENABLED` | `false` | Enable the fat-probe inside the censor pipeline |
| `FAT_PROBE_MIN_KB` / `FAT_PROBE_MAX_KB` | `1` / `30` | Drop-window bounds |
| `FAT_PROBE_ITERATIONS` | `16` | HEAD iterations |
| `FAT_PROBE_CHUNK_SIZE` | `4000` | Bytes of `X-Pad` per iteration |
| `FAT_PROBE_CONNECT_TIMEOUT` / `FAT_PROBE_READ_TIMEOUT` | `8.0` / `12.0` | Seconds |
| `FAT_PROBE_DEFAULT_SNI` | `example.com` | Fallback SNI for `dpi cdn-scan` |
| `SNI_BRUTE_MAX_CANDIDATES` | `200` | Cap for `dpi sni-brute` |
| `TELEGRAM_CHECK_ENABLED` | `false` | Include the Telegram probe in the censor pipeline |
| `TELEGRAM_STALL_TIMEOUT` | `10.0` | Read-stall timeout (seconds) |
| `TELEGRAM_TOTAL_TIMEOUT` | `60.0` | Cap for the full Telegram probe |

## DPI probes inside `serve`

These toggles enable a second periodic loop that runs DPI probes alongside the domain scan and exports `xray_dpi_*` metrics. Disabled by default — `serve` stays a pure domain scanner until you opt in.

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVE_DPI_ENABLED` | `false` | Master toggle — if `false`, no DPI loop runs regardless of other flags |
| `SERVE_DPI_INTERVAL_SECONDS` | `1800` | Period between DPI probe iterations (shared across DNS/CDN/Telegram). Standard domain scan uses `CHECK_INTERVAL_SECONDS` (default `300`) |
| `SERVE_DPI_DNS_ENABLED` | `false` | Run `probe_dns_integrity` each iteration |
| `SERVE_DPI_DNS_DOMAINS` | — | Comma-separated domains to probe. **Empty ⇒ DNS probe skipped even if enabled** |
| `SERVE_DPI_CDN_ENABLED` | `false` | Run `scan_targets` against bundled `tcp16_targets.json` |
| `SERVE_DPI_CDN_MAX_PARALLEL` | `10` | Concurrency for the CDN scan |
| `SERVE_DPI_CDN_LIMIT` | `0` | Cap on how many targets to probe (`0` = all) |
| `SERVE_DPI_TELEGRAM_ENABLED` | `false` | Run `check_telegram` (30 MB DL, 10 MB UL, 5 DC TCP ping) |

Fat-probe tuning (`FAT_PROBE_*`) and Telegram timeouts (`TELEGRAM_STALL_TIMEOUT` / `TELEGRAM_TOTAL_TIMEOUT`) are shared with the `xray-analyzer dpi` CLI.

## Logging & notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `LOG_FILE` | `xray-analyzer.log` | Structured log path |
| `NOTIFY_TELEGRAM_ENABLED` | `false` | Send problem reports to Telegram |
| `TELEGRAM_BOT_TOKEN` | — | Bot API token |
| `TELEGRAM_CHAT_ID` | — | Destination chat ID |

## Docker-Compose extras

These variables only affect `docker-compose.yml`; the analyzer itself ignores them.

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKER_EXTERNAL_PORT` | `2112` | Host port for Xray Checker |
| `METRICS_EXTERNAL_PORT` | `9090` | Host port for `/metrics` |
| `PROMETHEUS_EXTERNAL_PORT` | `9091` | Host port for Prometheus (`--profile monitoring`) |
| `GRAFANA_EXTERNAL_PORT` | `3000` | Host port for Grafana (`--profile monitoring`) |
| `GRAFANA_USER` / `GRAFANA_PASSWORD` | `admin` / `admin` | Grafana admin credentials |
| `METRICS_PROTECTED` | `false` | Enable basic auth on Xray Checker metrics |
| `METRICS_USERNAME` / `METRICS_PASSWORD` | — | Xray Checker metrics auth |
| `PROXY_CHECK_INTERVAL` | `300` | Xray Checker scan interval |
| `PROXY_CHECK_METHOD` | `ip` | Xray Checker check method |
| `PROXY_TIMEOUT` | `30` | Xray Checker per-proxy timeout |
| `CHECKER_LOG_LEVEL` | `info` | Xray Checker log level |
