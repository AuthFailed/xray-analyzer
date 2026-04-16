# Output model

How to read what the tool prints, emits, and exports.

- [Check statuses](#check-statuses)
- [Host-level roll-up](#host-level-roll-up)
- [Censor-check statuses and block types](#censor-check-statuses-and-block-types)
- [DPI error taxonomy](#dpi-error-taxonomy)
- [Prometheus metrics](#prometheus-metrics)
- [Exit codes](#exit-codes)

---

## Check statuses

Every individual diagnostic step emits a `CheckStatus`:

| Icon | Value | Meaning |
|------|-------|---------|
| `✓` | `PASS` | Check succeeded |
| `⚠` | `WARN` | Non-critical issue — noted but not failing (e.g., DNS disagrees with Check-Host but the path still works) |
| `✗` | `FAIL` | Hard failure |
| `⏱` | `TIMEOUT` | Exceeded the configured timeout — treated as `FAIL` for exit codes |
| `○` | `SKIP` | Intentionally skipped (usually because an earlier hard-fail made the step redundant) |

Every result also carries a `CheckSeverity` — `INFO`, `WARNING`, `ERROR`, or `CRITICAL` — which drives the host-level roll-up.

## Host-level roll-up

`HostDiagnostic.overall_status` is computed from the individual result statuses and severities:

| Result status | Result severity | Effect on host |
|---------------|-----------------|----------------|
| `FAIL` | `CRITICAL` / `ERROR` | Host → `FAIL` (hard) |
| `FAIL` | `WARNING` / `INFO` | Host → `WARN` (only if currently `PASS`; never demotes a `FAIL`) |
| `TIMEOUT` | any | Host → `FAIL` |
| `PASS` | any | No change |
| `SKIP` | any | No change |

In plain English: soft failures (warnings / info) only demote a previously-green host to `WARN`. Only hard failures (`ERROR`/`CRITICAL`) or timeouts set `FAIL`.

---

## Censor-check statuses and block types

`scan` and `serve` return a three-state verdict per domain:

| `DomainStatus` | Meaning |
|----------------|---------|
| `OK` | HTTP or HTTPS returned 2xx/3xx and no tampering evidence |
| `BLOCKED` | Something on the path prevented the request from reaching the site |
| `PARTIAL` | The request landed but was refused (4xx/5xx) or tampered with (DPI signal, but content still flowed) |

The `block_type` field on `DomainCheckResult` narrows down **why**:

| `block_type` | What happened |
|-------------|---------------|
| `DNS` | Name resolution failed entirely |
| `DNS-SPOOF` | Resolver returned a known RKN stub (Rostelecom / MTS / Beeline / Megafon) or a bogon IP |
| `IP/TCP` | DNS ok but TCP 443 + 80 both closed |
| `IP/HTTP` | TCP closed and no HTTP response either |
| `TLS/SSL` | TLS certificate could not be validated |
| `HTTP(S)` | HTTP and HTTPS both returned zero bytes (connection reset mid-request) |
| `HTTP-RESPONSE` | Both HTTP and HTTPS returned 4xx–5xx — site reachable but refusing |
| `REGIONAL` | Page content matches an AI/social-geoblock pattern (ChatGPT, Grok, Netflix, etc.) |
| `…/DPI` | Composite — one of the above **plus** at least one strong DPI signal (SNI variance confirmed, host-header injection, 192.0.2.1 fast-RST, DoH mismatch) |

Strong DPI signals are trusted; the bare keyword probe stays a soft signal and never elevates `block_type` on its own.

---

## DPI error taxonomy

Every DPI probe classifies its failure through one stable `ErrorLabel` (defined in `src/xray_analyzer/diagnostics/error_classifier.py`). Labels are determined by walking the `__cause__` / `__context__` chain of the raised exception and mapping it to:

| Label | Triggered by |
|-------|--------------|
| `OK` | success |
| `DNS_FAIL` | NXDOMAIN, SERVFAIL, `socket.gaierror`, resolver timeout |
| `DNS_FAKE` | suspicious IP (stub, 198.18/15 benchmarking, bogon) |
| `TCP_TIMEOUT` | plain TCP/L4 timeout |
| `TCP_REFUSED` | RST during handshake / `ECONNREFUSED` |
| `TCP_RST` | RST mid-stream |
| `TCP_ABORT` | `ECONNRESET` / `ECONNABORTED` |
| `NET_UNREACH` | `ENETUNREACH` |
| `HOST_UNREACH` | `EHOSTUNREACH` |
| `POOL_TIMEOUT` | aiohttp pool timeout (no socket available) |
| `TLS_DPI` | TLS alert / handshake failure consistent with middle-box fingerprinting |
| `TLS_MITM` | invalid certificate (self-signed, unknown CA, expired, hostname mismatch) |
| `TLS_BLOCK` | explicit version/cipher protocol alert |
| `TCP_16_20` | connection dropped inside the 1–30 KB fat-probe window (RU DPI ciphertext cap) |
| `ISP_PAGE` | HTTP 451 / cross-domain redirect to a known ISP splash |
| `READ_ERR` | generic read-side disconnect after connection established |
| `GENERIC` | fallback |

---

## Prometheus metrics

Exposed at `GET /metrics` by `xray-analyzer serve` in the Prometheus text format (v0.0.4).

| Metric | Type | Labels | Value |
|--------|------|--------|-------|
| `xray_domain_accessible` | gauge | `domain`, `status`, `block_type`, `proxy` | `1` OK, `0.5` PARTIAL, `0` BLOCKED |
| `xray_domain_http_code` | gauge | `domain`, `scheme` (`http` / `https`), `proxy` | HTTP code, `0` if no response |
| `xray_domain_tls_valid` | gauge | `domain`, `proxy` | `1` valid cert, `0` invalid/absent |
| `xray_domain_dpi_detected` | gauge | `domain`, `proxy` | `1` if any DPI signal tripped |
| `xray_scan_domains_total` | gauge | `proxy` | Domain count in last scan |
| `xray_scan_domains_ok` | gauge | `proxy` | OK count |
| `xray_scan_domains_blocked` | gauge | `proxy` | BLOCKED count |
| `xray_scan_domains_partial` | gauge | `proxy` | PARTIAL count |
| `xray_scan_last_run_timestamp_seconds` | gauge | `proxy` | Unix time of last scan end |
| `xray_scan_duration_seconds` | gauge | `proxy` | Last scan wall time |
| `xray_scan_up` | gauge | `proxy` | `1` last scan succeeded, `0` errored or still pending |

The `proxy` label is:

- `direct` when no proxy is configured
- The share-link name (or `host:port` fallback) when running `serve --subscription`
- The raw proxy URL otherwise

### Health endpoint

`GET /health`:

- `200 OK` after the first successful scan
- `503` while waiting for the first scan
- `500` if the first scan errored

---

## Exit codes

All commands follow Unix convention:

| Code | When |
|------|------|
| `0` | Success — all checks passed, or at least one proxy/domain succeeded (command-dependent) |
| `1` | Failure — one or more checks failed, or the command errored |

Command-specific notes:

- `analyze` — `0` iff every host rolls up to `PASS` or `WARN`; any `FAIL` returns `1`.
- `check` — `0` if the domain's `overall_status` is `PASS` or `WARN`.
- `check --subscription` — `0` if at least one proxy succeeded.
- `scan` — `0` iff zero domains are `BLOCKED` (`PARTIAL` does not fail).
- `serve` — runs forever; exits `0` on SIGINT, `1` on fatal setup error.
- `dpi dns` — `0` iff **every** domain is `ok`.
- `dpi tcp16` — `0` iff `label == "ok"`.
- `dpi cdn-scan` — `0` iff overall verdict is `ok`.
- `dpi sni-brute` — `0` if at least one working SNI is found.
- `dpi telegram` — `0` iff every leg (DL, UL, DC ping) passes.
