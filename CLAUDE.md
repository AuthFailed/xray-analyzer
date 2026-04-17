# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
uv sync

# Run all tests
uv run pytest

# Run a single test file
uv run pytest tests/test_censor_checker.py

# Run a single test by name
uv run pytest tests/test_censor_checker.py::TestIsRknSpoof::test_known_rkn_ip

# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format src/ tests/

# Run the CLI — analyze proxies from subscription or direct links
uv run xray-analyzer analyze --subscription-url https://sub.example.com/link
uv run xray-analyzer analyze vless://uuid@server:443?security=tls
uv run xray-analyzer analyze --subscription-url https://... --watch

# check: single domain step-by-step diagnosis (DNS → TCP → ping → TLS → HTTP → DPI)
uv run xray-analyzer check meduza.io
uv run xray-analyzer check meduza.io --proxy socks5://127.0.0.1:1080

# scan: bulk censorship scan across many domains (parallel, progress bar)
uv run xray-analyzer scan                                 # built-in default list
uv run xray-analyzer scan google.com youtube.com          # specific domains
uv run xray-analyzer scan --list whitelist                # Russia mobile whitelist
uv run xray-analyzer scan --proxy socks5://127.0.0.1:1080

# dpi: deep DPI / censorship probes (adapted from Runnin4ik/dpi-detector)
uv run xray-analyzer dpi dns meduza.io youtube.com        # UDP vs DoH + stub-IP harvest
uv run xray-analyzer dpi tcp16 5.161.249.234 --sni example.com  # fat-probe 16-20 KB throttle
uv run xray-analyzer dpi cdn-scan --max-parallel 20       # ASN-bucketed CDN/hosting scan
uv run xray-analyzer dpi sni-brute 5.161.249.234 --max 50 # find a working SNI for a blocked IP
uv run xray-analyzer dpi telegram                         # Telegram DL / UL / DC reachability
```

## Architecture

The tool is an async Python diagnostics engine for Xray proxy servers. Proxies are provided via **subscription URL** or **direct share links** (vless://, trojan://, ss://). The analyzer runs a battery of checks on each proxy.

### Data flow

1. `cli.py` — argparse entry point, dispatches to async `cmd_*` coroutines
2. `core/standalone_analyzer.py` — main orchestrator; takes `ProxyShareURL` list from subscription or CLI args, runs all checks concurrently, then runs cross-proxy tests for problematic hosts
3. `diagnostics/subscription_parser.py` — parses subscription URLs and individual share links into `ProxyShareURL` objects
4. `diagnostics/` — individual check functions, each returning a `DiagnosticResult`
5. `notifiers/` — pluggable notifiers (Telegram); `NotifierManager` fans out to all enabled notifiers

### Check pipeline (per proxy)

For each proxy `analyze_single_proxy` runs:
1. DNS resolution with Check-Host.net comparison (`dns_checker.py`)
2. TCP connection (`tcp_checker.py`)
3. TCP ping (`tcp_ping_checker.py`) — only if TCP connection passed
4. For **VLESS/Trojan/SS** proxies: spawns an `XrayInstance` and tests connectivity (`proxy_xray_checker.py`, `xray_manager.py`)
5. For **HTTP/SOCKS** proxies: TCP tunnel, exit IP, SNI checks

After all proxies are analyzed, the orchestrator runs cross-proxy tests on problematic hosts — testing them *through* a known-working proxy to distinguish local network issues from server-side failures.

A `_DirectProbeCache` deduplicates DNS/TCP/Ping probes when multiple proxies share the same backing server (common in subscriptions).

### Key models (`core/models.py`)

- `DiagnosticResult` — result of one check: `check_name`, `status` (`CheckStatus`), `severity` (`CheckSeverity`), `message`, `details` dict, `duration_ms`
- `HostDiagnostic` — aggregate for one host: list of `DiagnosticResult`, `overall_status`, `recommendations`

### Configuration (`core/config.py`)

All settings are loaded from `.env` via `pydantic-settings`. The singleton `settings` object is imported directly. Key non-obvious settings:
- `SUBSCRIPTION_URL` — subscription URL with VLESS/Trojan/SS share links
- `XRAY_BINARY_PATH` — path to xray binary; auto-downloaded if not found
- `RKN_THROTTLE_CHECK_ENABLED` — enables 16–20 KB DPI throttle detection

### DPI probe modules (`diagnostics/*_probe*.py`, `*_checker.py`, `cli_dpi.py`)

Tier 1–6 probes adapted from [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT). All share `error_classifier.classify()` which walks `__cause__`/`__context__` chains and maps exceptions to a stable `ErrorLabel` taxonomy (`TLS_DPI`, `TLS_MITM`, `TLS_BLOCK`, `TCP_16_20`, `TCP_RST`, `TCP_ABORT`, `TCP_REFUSED`, `TCP_TIMEOUT`, `NET_UNREACH`, `HOST_UNREACH`, `DNS_FAIL`, `DNS_FAKE`, `ISP_PAGE`, `POOL_TIMEOUT`, `READ_ERR`, `GENERIC`).

- `dns_dpi_prober.py` — raw UDP (9 resolvers) vs DoH JSON (7 resolvers) cross-check; harvests "stub IPs" that appear ≥2× across UDP answers.
- `tls_version_probe.py` + `http_injection_probe.py` — forced-TLS-1.2/1.3 probes and plain HTTP-80 injection check; share `evaluate_response` for ISP-splash / HTTP-451 / cross-domain-redirect detection.
- `fat_probe_checker.py` — keepalive-reused socket + 16 HEAD iterations with 4 KB `X-Pad` junk; drop inside the 1-30 KB window → `TCP_16_20`. Supports IP+SNI override via a custom `aiohttp.AbstractResolver`.
- `cdn_target_scanner.py` — bulk fat-probe against `data/tcp16_targets.json`, grouped by ASN/provider.
- `sni_brute_force_checker.py` — iterates `data/whitelist_sni.txt` with `hint_rtt_ms` to find a working SNI on a blocked CDN IP.
- `telegram_checker.py` — concurrent 30 MB DL, 10 MB UL, TCP ping of all 5 DC IPs.

Bundled data (`src/xray_analyzer/data/`): `dns_servers.json`, `tcp16_targets.json`, `whitelist_sni.txt` — see `data/CREDITS.md` for upstream attribution.

### Test conventions

Tests use `pytest-asyncio` with `asyncio_mode = "auto"`. HTTP mocking uses `aioresponses`. Tests live in `tests/` with one file per module.