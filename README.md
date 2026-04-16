# Xray Analyzer

[English](README.md) · [Русский](README.ru.md)

Advanced async diagnostics toolkit for Xray proxy servers and for the network paths between you and the open web.

Combines a full proxy-health pipeline, a six-tier DPI / censorship probe suite, a bulk censorship scanner, and a Prometheus metrics daemon — in one `uv run xray-analyzer` CLI.

## Features

- **Proxy fleet diagnostics** — talks to an [Xray Checker](https://github.com/kutovoy/xray-checker) API (or a raw subscription URL) and runs 8–12 targeted checks per offline proxy: DNS, TCP, ping, RKN blocklist, Xray tunnel, exit-IP, SNI, DPI 16–20 KB throttle.
- **Single-host step-by-step diagnosis** — `check <domain>` walks DNS → TCP → ping → TLS → HTTP → DPI in order, printing each step live.
- **Bulk censorship scan** — `scan` iterates hundreds of domains in parallel with a live progress bar; built-in list plus community blocklists (`whitelist`, `russia-inside`, `russia-outside`, `ukraine-inside`).
- **DPI deep probes** — direct-UDP vs DoH DNS cross-check, TLS 1.2/1.3 split, HTTP injection detection, keepalive "fat-probe" for the 16–20 KB TCP drop, bulk CDN/ASN scan, SNI brute-force, Telegram DC reachability.
- **Prometheus exporter** — `serve` runs periodic scans and exposes per-domain / per-proxy metrics at `/metrics`.
- **Telegram notifier** — formatted problem reports to a chat.
- **Docker-first** — one `docker compose up` starts the checker + analyzer + optional Prometheus/Grafana stack.

Built on `aiohttp`, `pydantic-settings`, `rich`, `structlog`. Runs on Python 3.14+.

## Quick start

### Docker Compose (recommended)

```bash
cp .env.example .env
# edit .env — at minimum set SUBSCRIPTION_URL
docker compose up -d
docker compose logs -f xray-analyzer
```

Add the `monitoring` profile for Prometheus + Grafana:

```bash
docker compose --profile monitoring up -d
# Prometheus → http://localhost:9091
# Grafana    → http://localhost:3000   (admin/admin)
```

### Local

```bash
git clone https://github.com/AuthFailed/xray-analyzer
cd xray-analyzer
uv sync
uv run xray-analyzer --help
```

The Xray binary is auto-downloaded on first use when VLESS/Trojan/SS tunnel testing is requested and no `XRAY_BINARY_PATH` is on `$PATH`.

## First commands

```bash
uv run xray-analyzer analyze                          # fleet diagnostics
uv run xray-analyzer check meduza.io                  # single-domain walkthrough
uv run xray-analyzer scan --list whitelist            # bulk censorship scan
uv run xray-analyzer serve --port 9090                # Prometheus /metrics daemon
uv run xray-analyzer dpi tcp16 5.161.249.234          # 16-20 KB DPI fat-probe
```

## Documentation

- **[CLI reference](docs/en/cli.md)** — every command, every flag, sample output
- **[Configuration](docs/en/configuration.md)** — all environment variables
- **[Output model](docs/en/output.md)** — statuses, block types, DPI error labels, Prometheus metrics, exit codes
- **[Architecture](docs/en/architecture.md)** — pipeline flow, module map, standalone vs checker-API modes
- **[Development](docs/en/development.md)** — how to run tests, lint, type-check, contribute

## License

MIT.

## Attribution

- Tier 1–6 DPI probes ported from [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT).
- `scan` replicates the domain-censorship heuristics of [@tracerlab](https://t.me/tracerlab)'s bash script.
- Bundled domain lists — see [`src/xray_analyzer/data/CREDITS.md`](src/xray_analyzer/data/CREDITS.md).
- The Xray Checker API is provided by [kutovoy/xray-checker](https://github.com/kutovoy/xray-checker).
