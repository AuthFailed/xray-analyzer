# Architecture

## Data flow

```
                 ┌──────────────────────┐
                 │ CLI (argparse)       │ cli.py / cli_dpi.py
                 └──────────┬───────────┘
                            │
              ┌─────────────▼──────────────┐
              │ analyze_subscription_      │ core/standalone_analyzer.py
              │   proxies (orchestrator)   │
              └──┬─────────────────────┬───┘
                 │                     │
         parses  │                     │ runs per-proxy pipeline
    share links  │                     │ via asyncio.gather
                 │                     │
         ┌───────▼────┐ ┌────────────┐ │
         │ Subscription│ │ Xray      │ │
         │ parser     │ │ binary    │ │
         └────────────┘ └───────────┘ │
                                      │
        ┌─────────────────────────────▼───────────────────────┐
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
                    │   → telegram, etc.     │
                    └────────────────────────┘
```

## Check pipeline per proxy

`core/standalone_analyzer.py::analyze_subscription_proxies` runs these sequentially for each proxy:

1. **DNS resolution** with Check-Host.net comparison — `dns_checker.py`
2. **TCP connection** — `tcp_checker.py`
3. **TCP ping** — `tcp_ping_checker.py`
4. **RKN block check** via `rknweb.ru` API — `rkn_checker.py`
5. **For VLESS/Trojan/SS** (if `SUBSCRIPTION_URL` set): spawn an `XrayInstance`, test connectivity — `proxy_xray_checker.py`, `xray_manager.py`
6. **For HTTP/SOCKS**: TCP tunnel, exit IP, SNI, legacy tunnel — `proxy_tcp_checker.py`, `proxy_ip_checker.py`, `proxy_sni_checker.py`, `tunnel_checker.py`

After every proxy has been analyzed, the orchestrator performs two global passes:

- **Cross-proxy retest** — any problematic host is re-tried through a known-working proxy to distinguish local network issues from server-side failures (`proxy_cross_checker.py`).
- **RKN DPI throttle** — 16–20 KB cutoff detection, both directly and through the working proxy (`proxy_rkn_throttle_checker.py`, `core/throttle_checker_runner.py`).

## DPI probe stack

The `xray-analyzer dpi ...` subcommands are adapted from [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT). Every probe funnels its exception handling through `error_classifier.classify()`, which walks the exception chain and emits a stable `ErrorLabel` — `TLS_DPI`, `TCP_16_20`, `ISP_PAGE`, etc. (see [output.md#dpi-error-taxonomy](output.md#dpi-error-taxonomy)).

| Module | Role |
|--------|------|
| `dns_dpi_prober.py` | UDP (9 resolvers) vs DoH JSON (7 resolvers); harvests stub IPs that appear ≥2× |
| `tls_version_probe.py` | Forced TLS 1.2 / 1.3 probes |
| `http_injection_probe.py` | Plain HTTP-80 injection detection; shares `evaluate_response` with TLS probe for ISP-splash / HTTP-451 / cross-domain-redirect detection |
| `fat_probe_checker.py` | Keepalive-reused socket + 16 HEAD iterations with 4 KB `X-Pad` junk; drop inside 1–30 KB window → `TCP_16_20`. Supports IP+SNI override via a custom `aiohttp.AbstractResolver` |
| `cdn_target_scanner.py` | Bulk fat-probe against `data/tcp16_targets.json`, grouped by ASN / provider |
| `sni_brute_force_checker.py` | Iterates `data/whitelist_sni.txt` with `hint_rtt_ms` to find a working SNI for a blocked CDN IP |
| `telegram_checker.py` | Concurrent 30 MB DL + 10 MB UL + TCP ping of all 5 DC IPs |

Bundled reference data lives under `src/xray_analyzer/data/`:

- `dns_servers.json` — UDP + DoH resolver list
- `tcp16_targets.json` — CDN/hosting IPs grouped by ASN
- `whitelist_sni.txt` — SNI candidate list for brute-force

See `data/CREDITS.md` for upstream attribution.

## Metrics server

`metrics/server.py` implements a tiny aiohttp server exposing `/metrics` (Prometheus text format v0.0.4) and `/health`. It writes the text format by hand — no `prometheus-client` dependency — and the state is an in-memory `MetricsState` mutated in the same event loop that runs the scans, so no locking is needed.

When `serve --subscription` is used, each proxy gets its own entry in `MetricsState._entries` keyed by label (share-link name or `host:port`), so every metric is emitted once per proxy.

## Project layout

```
src/xray_analyzer/
├── cli.py                            # argparse entry point, command dispatch
├── cli_dpi.py                        # xray-analyzer dpi ... subcommand group
├── core/
│   ├── standalone_analyzer.py        # main orchestrator (analyze_subscription_proxies)
│   ├── config.py                     # pydantic-settings Settings singleton
│   ├── cross_proxy_tests.py          # retest failing hosts via a working proxy
│   ├── logger.py                     # structlog setup
│   ├── models.py                     # DiagnosticResult / HostDiagnostic / CheckStatus
│   ├── proxy_url.py                  # build_proxy_url helpers
│   ├── recommendation_engine.py      # maps failure combos → human fixes
│   └── throttle_checker_runner.py    # batched 16-20 KB probes
├── diagnostics/
│   ├── dns_checker.py                # local DNS + Check-Host.net cross-check
│   ├── dns_dpi_prober.py             # UDP vs DoH + stub-IP harvest
│   ├── tcp_checker.py                # TCP connect test
│   ├── tcp_ping_checker.py           # TCP ping / latency
│   ├── tls_version_probe.py          # forced TLS 1.2 / 1.3 probes
│   ├── http_injection_probe.py       # plain HTTP-80 injection detection
│   ├── fat_probe_checker.py          # TCP 16-20 KB fat-probe
│   ├── cdn_target_scanner.py         # bulk fat-probe across CDN/ASN buckets
│   ├── sni_brute_force_checker.py    # whitelist-driven SNI search
│   ├── telegram_checker.py           # Telegram DL/UL/DC reachability
│   ├── rkn_checker.py                # rknweb.ru blocklist API
│   ├── proxy_tcp_checker.py          # proxy TCP tunnel probe
│   ├── proxy_ip_checker.py           # proxy exit-IP probe
│   ├── proxy_sni_checker.py          # SNI through the proxy
│   ├── proxy_cross_checker.py        # cross-proxy availability
│   ├── proxy_rkn_throttle_checker.py # 16-20 KB probe via proxy
│   ├── proxy_xray_checker.py         # VLESS/Trojan/SS tunnel via Xray
│   ├── xray_manager.py               # XrayInstance process lifecycle
│   ├── xray_downloader.py            # auto-download Xray binary from GitHub
│   ├── subscription_parser.py        # parse vless://, trojan://, ss:// share URLs
│   ├── error_classifier.py           # stable exception → ErrorLabel taxonomy
│   └── censor_checker.py             # bulk scan pipeline
├── metrics/
│   └── server.py                     # aiohttp-based /metrics + /health
├── notifiers/
│   ├── base.py                       # Notifier Protocol
│   ├── telegram.py                   # Telegram bot notifier
│   └── manager.py                    # fan-out to enabled notifiers
└── data/                             # bundled DNS resolvers, CDN targets, SNI whitelist
```
