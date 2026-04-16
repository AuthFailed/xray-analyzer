# CLI reference

Every command is async, prints Rich-styled output, and exits with code `0` on success / `1` on failure or when blocks/problems are detected.

**Commands:**

- [`analyze`](#analyze) — fleet diagnostics over every proxy from the checker API or a subscription URL
- [`check`](#check) — single-domain step-by-step diagnosis
- [`scan`](#scan) — bulk censorship scan across many domains
- [`serve`](#serve) — periodic `scan` with Prometheus `/metrics` endpoint
- [`status`](#status) — health of the configured Xray Checker API
- [`dpi dns`](#dpi-dns) — direct-UDP vs DoH DNS integrity probe
- [`dpi tcp16`](#dpi-tcp16) — single fat-probe for the 16–20 KB TCP drop
- [`dpi cdn-scan`](#dpi-cdn-scan) — bulk fat-probe grouped by ASN / provider
- [`dpi sni-brute`](#dpi-sni-brute) — whitelist-driven SNI search against a blocked IP
- [`dpi telegram`](#dpi-telegram) — Telegram DL / UL / DC reachability

---

## `analyze`

Full pipeline over every proxy returned by the Xray Checker API, or every share link in a subscription when running *standalone* (no checker API — just `SUBSCRIPTION_URL`).

```bash
uv run xray-analyzer analyze
uv run xray-analyzer analyze --watch
uv run xray-analyzer analyze --subscription-url https://example/sub --no-xray
```

| Flag | Default | Description |
|------|---------|-------------|
| `--watch` | off | Loop forever, re-running at `CHECK_INTERVAL_SECONDS` (min 60 s) |
| `--subscription-url <URL>` | env | Override `SUBSCRIPTION_URL` |
| `--subscription-hwid <HWID>` | env | `x-hwid` header for the subscription fetch |
| `--checker-api-url <URL>` | env | Override `CHECKER_API_URL` |
| `--checker-api-username / --checker-api-password` | env | Basic auth for the checker |
| `--analyze-online` | off | Also re-check proxies the checker reports as *online* |
| `--no-xray` | off | Skip the VLESS/Trojan/SS tunnel test |
| `--no-rkn-throttle` | off | Skip the 16–20 KB DPI probe |
| `--no-sni` | off | Skip the SNI-through-proxy test |
| `--check-host-api-key <KEY>` | env | API key for Check-Host.net DNS comparison |
| `--proxy-status-url / --proxy-ip-url / --sni-domain` | env | Override the default tunnel URLs |
| `--interval <SECONDS>` | env | Override `CHECK_INTERVAL_SECONDS` for `--watch` |

### Pipeline per proxy

1. **DNS** — local resolver cross-checked against Check-Host.net probes from multiple countries.
2. **TCP connection** — port 443 open.
3. **TCP ping** — round-trip latency.
4. **RKN blocklist** — `rknweb.ru` API.
5. **Proxy tunnel** — for VLESS/Trojan/SS: spawn an `XrayInstance` and verify the tunnel + exit IP. For HTTP/SOCKS: TCP tunnel, exit IP, SNI, legacy HTTP tunnel.
6. **Cross-proxy retest** — any failing host is re-tried through a known-good proxy to isolate local-network issues from server-side failures.
7. **RKN DPI throttle** — 16–20 KB ciphertext cutoff detection (directly and through the working proxy).

### Output

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

Compact-table columns:

- **DNS** — local resolver agrees with Check-Host.net (no DNS poisoning).
- **TCP / Ping** — port 443 opens and latency is measurable.
- **RKN Thr** — no 16–20 KB drop detected.
- **Proxy** — Xray tunnel (VLESS/Trojan/SS) or HTTP/SOCKS tunnel test succeeded.

---

## `check`

Walks a single host through the full censorship-diagnosis pipeline, live. Useful for debugging "why is this one domain not loading?".

```bash
uv run xray-analyzer check meduza.io
uv run xray-analyzer check meduza.io --port 8443
uv run xray-analyzer check meduza.io --proxy socks5://127.0.0.1:1080
uv run xray-analyzer check meduza.io --proxy 'vless://...@host:443?...'
uv run xray-analyzer check meduza.io --subscription https://example/sub
```

| Argument | Default | Description |
|----------|---------|-------------|
| `host` | required | Domain or IP to diagnose |
| `--port <N>` | `443` | Port for TCP/TLS probes |
| `--proxy <URL>` | env | HTTP/SOCKS URL, or a VLESS/Trojan/SS share link (the latter is auto-launched via Xray on `socks5://127.0.0.1:<auto>`) |
| `--timeout <SECONDS>` | env | Per-step timeout override |
| `--subscription <URL>` | — | Test the domain through **every** VLESS/Trojan/SS link in the subscription (max 8 concurrent Xray instances); prints a per-proxy table at the end |

### Output — single-proxy mode

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

Each step is labelled with one of the icons in [output.md#check-statuses](output.md#check-statuses). `SKIP` means the step was intentionally not run (usually because an earlier hard-fail would make it redundant).

### Output — subscription mode

One line per proxy while running, then a summary table:

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

Exit code `0` if at least one proxy succeeds.

---

## `scan`

Parallel censorship scan across many domains. DNS + RKN-stub detection, TCP on 443/80, TLS certificate validation, HTTP/HTTPS request codes, and a DPI signal suite (SNI variance, host-header injection, fast-RST probe, DoH mismatch).

```bash
uv run xray-analyzer scan                                    # built-in ~30-domain list
uv run xray-analyzer scan google.com youtube.com             # explicit set
uv run xray-analyzer scan --list whitelist                   # Russia mobile whitelist
uv run xray-analyzer scan --list russia-inside               # itdoginfo/allow-domains
uv run xray-analyzer scan --file ./domains.txt
uv run xray-analyzer scan --proxy socks5://127.0.0.1:1080 --max-parallel 20
```

| Argument | Default | Description |
|----------|---------|-------------|
| `domains` (positional) | — | Explicit domain list (overrides `--list` / `--file` / config) |
| `--list <name>` | `default` | `default` / `whitelist` / `russia-inside` / `russia-outside` / `ukraine-inside` |
| `--file <PATH>` | — | Text file with one domain per line (`#` comments allowed, invalid lines flagged) |
| `--proxy <URL>` | env | HTTP/SOCKS/Xray share URL |
| `--timeout <SECONDS>` | `4` | Per-domain timeout |
| `--max-parallel <N>` | `10` | Concurrency cap |

Exit code `1` if at least one domain is `BLOCKED`.

### Output

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

See [output.md#censor-check-statuses-and-block-types](output.md#censor-check-statuses-and-block-types) for what each `block_type` means.

---

## `serve`

Run `scan` on a schedule and expose Prometheus metrics.

```bash
uv run xray-analyzer serve
uv run xray-analyzer serve --port 9100 --interval 120
uv run xray-analyzer serve --list whitelist --proxy socks5://127.0.0.1:1080
uv run xray-analyzer serve --subscription https://example/sub
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port <N>` | `9090` (env `METRICS_PORT`) | Listen port |
| `--host <IP>` | `0.0.0.0` (env `METRICS_HOST`) | Bind address |
| `--interval <SECONDS>` | `CHECK_INTERVAL_SECONDS` | Time between scans |
| `domains` / `--list` / `--file` | same as `scan` | Target domain set |
| `--proxy <URL>` | env | Single proxy for all scans |
| `--subscription <URL>` | — | Scan through **every** VLESS/Trojan/SS proxy in the subscription; each proxy gets its own label in every metric |
| `--timeout` / `--max-parallel` | env | Per-domain limits |

### Endpoints

- `GET /metrics` — Prometheus text format v0.0.4 — see [output.md#prometheus-metrics](output.md#prometheus-metrics).
- `GET /health` — `200` once the first scan succeeds, `503` while waiting, `500` if the first scan errored.

### DPI probes alongside the scan

Set `SERVE_DPI_ENABLED=true` and at least one probe toggle (`SERVE_DPI_DNS_ENABLED`, `SERVE_DPI_CDN_ENABLED`, `SERVE_DPI_TELEGRAM_ENABLED`) to run DNS/CDN/Telegram DPI checks on their own schedule (`SERVE_DPI_INTERVAL_SECONDS`, default `1800`s) alongside the regular domain scan. Results are exposed as `xray_dpi_*` metrics — see [configuration.md](configuration.md#dpi-probes-inside-serve) and [output.md](output.md#dpi-probe-metrics).

### Output

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

In `--subscription` mode, one progress line per proxy is printed per cycle.

---

## `status`

Quick health check of the configured Xray Checker API.

```bash
uv run xray-analyzer status
```

### Output

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

Cross-check direct UDP/53 against DoH JSON; harvest "stub IPs" that appear ≥2× across UDP answers (typical of ISP splash pages).

```bash
uv run xray-analyzer dpi dns meduza.io youtube.com
uv run xray-analyzer dpi dns meduza.io --udp-only
uv run xray-analyzer dpi dns meduza.io --doh-only --timeout 8
```

| Flag | Default | Description |
|------|---------|-------------|
| `domains` (nargs+) | required | Domain list |
| `--timeout <SECONDS>` | `5.0` | Per-query timeout |
| `--udp-only` / `--doh-only` | — | Disable one side of the cross-check |

### Output

```
DNS integrity probe — 2 domain(s)
  UDP: 8.8.8.8 (Google)
  DoH: https://cloudflare-dns.com/dns-query (Cloudflare)
  Stub IPs harvested: 195.208.4.1

Domain        Verdict   UDP answer    DoH answer
meduza.io     spoof     195.208.4.1   95.213.4.17
youtube.com   ok        142.250.x.x   142.250.x.x
```

### Verdicts

- `ok` — UDP and DoH agree.
- `spoof` — UDP returns a different IP set that includes a stub/bogon.
- `intercept` — UDP times out, DoH works (UDP/53 blackholed).
- `fake_nxdomain` / `fake_empty` — UDP says NXDOMAIN / nothing, DoH works.
- `doh_blocked` — DoH fails, UDP works.
- `all_dead` — neither resolver answers.

Exit code `0` only if every domain is `ok`.

---

## `dpi tcp16`

One-off fat-probe against a specific IP/SNI pair, looking for the 16–20 KB TCP drop signature.

```bash
uv run xray-analyzer dpi tcp16 5.161.249.234
uv run xray-analyzer dpi tcp16 5.161.249.234 --sni example.com --iterations 20
```

| Flag | Default | Description |
|------|---------|-------------|
| `target` | required | IP or hostname |
| `--port <N>` | `443` | TCP port |
| `--sni <name>` | — | Force SNI ≠ target (TLS lands at `target`'s IP but advertises this hostname) |
| `--iterations <N>` | `16` | HEAD iterations with growing `X-Pad`; each adds ~4 KB ciphertext |

### How it works

Opens a single aiohttp session with `TCPConnector(limit=1, force_close=False)` so every HEAD reuses the same TCP socket. Iteration 0 is a clean HEAD (measures liveness + RTT). Iterations 1..N-1 add cumulative 4 KB `X-Pad` junk. Drops typically land between iter 4 and iter 5 (~16–20 KB).

### Output

```
Fat-probe 5.161.249.234:443 (SNI=example.com)
PASS TCP 16-20 KB Fat Probe: all 16 iterations succeeded (~64 KB ciphertext)
```

or

```
FAIL TCP 16-20 KB Fat Probe: drop at ≈16 KB (TCP_16_20)
```

The `label` field in `details` is one of the [DPI error labels](output.md#dpi-error-taxonomy). `TCP_16_20` is the signature we're hunting.

---

## `dpi cdn-scan`

Bulk fat-probe against the bundled CDN/hosting IP list (`src/xray_analyzer/data/tcp16_targets.json`), grouped by ASN and provider.

```bash
uv run xray-analyzer dpi cdn-scan
uv run xray-analyzer dpi cdn-scan --max-parallel 20 --limit 50
```

| Flag | Default | Description |
|------|---------|-------------|
| `--max-parallel <N>` | `10` | Concurrent fat-probes |
| `--limit <N>` | `0` (all) | First N targets only |

### Output

```
CDN scan — 84 targets, parallelism 20
Provider     ASN       OK / Total   Blocked   Verdict
Cloudflare   AS13335   12/12        0         ok
Hetzner      AS24940   4/8          4         partial
Rostelecom   AS12389   0/6          6         blocked
…
Overall: partial
```

Per-bucket `verdict` is `ok` (no drops), `partial` (some drops), `blocked` (every target drops). Use it to pick an unblocked provider before hosting a new proxy.

---

## `dpi sni-brute`

Iterate a large whitelist of domains trying to find one whose SNI passes DPI at the target IP — useful for REALITY / SNI-masquerade tuning.

```bash
uv run xray-analyzer dpi sni-brute 5.161.249.234 --max 50
uv run xray-analyzer dpi sni-brute 5.161.249.234 --early-exit 3
```

| Flag | Default | Description |
|------|---------|-------------|
| `target` | required | IP or hostname |
| `--port <N>` | `443` | TCP port |
| `--max <N>` | `200` | Maximum candidates from `data/whitelist_sni.txt` |
| `--early-exit <N>` | `1` | Stop after finding this many working SNIs |

### Output

```
SNI brute-force against 5.161.249.234:443 (cap=50)
PASS SNI Brute-force: found 1 working SNI
Working SNIs:
  • cdn.jsdelivr.net
```

Exit code `0` if at least one working SNI is found.

---

## `dpi telegram`

Probe Telegram reachability — 30 MB download, 10 MB upload, TCP ping of every Telegram DC.

```bash
uv run xray-analyzer dpi telegram
uv run xray-analyzer dpi telegram --via-proxy socks5://127.0.0.1:1080
uv run xray-analyzer dpi telegram --total-timeout 120
```

| Flag | Default | Description |
|------|---------|-------------|
| `--via-proxy <URL>` | — | Route all Telegram traffic through this proxy |
| `--total-timeout <SECONDS>` | `60` | Cap for the whole probe |

### Output

```
Telegram reachability probe — DL + UL + DC ping (~30 MB download)
PASS Telegram Reachability: all checks green
  Download: PASS, 30.0 MB in 4.8s
  Upload:   PASS, 10.0 MB in 2.1s
  DCs reachable: 5/5
```

Exit code `0` iff every leg passes.
