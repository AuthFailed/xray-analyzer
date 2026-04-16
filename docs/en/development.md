# Development

## Prerequisites

- **Python ≥ 3.14**
- [`uv`](https://github.com/astral-sh/uv) — the project uses it for dependency and venv management
- `git`, standard build tools

```bash
git clone https://github.com/AuthFailed/xray-analyzer
cd xray-analyzer
uv sync --all-extras --dev
```

## Commands

```bash
# Full test suite
uv run pytest

# Single test file / test
uv run pytest tests/test_censor_checker.py
uv run pytest tests/test_censor_checker.py::TestIsRknSpoof::test_known_rkn_ip

# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format src/ tests/

# Type check
uv run ty check

# CLI entry point (same as docker)
uv run xray-analyzer --help
```

## Test conventions

- Tests live under `tests/`, one file per source module (`tests/test_<module>.py`).
- `pytest-asyncio` runs in `auto` mode — every `async def test_*` is treated as an async test automatically (`pyproject.toml::[tool.pytest.ini_options]::asyncio_mode = "auto"`).
- HTTP is mocked with [`aioresponses`](https://github.com/pnuckowski/aioresponses) — no live network calls in tests.
- 214 tests currently; run under ~13 s on a typical laptop.

## Continuous integration

`.github/workflows/ci.yml` runs on every push / PR to `main`:

1. `uv sync --all-extras --dev`
2. `uv run ruff check src/ tests/`
3. `uv run ruff format --check src/ tests/`
4. `uv run ty check`
5. `uv run pytest`

All five steps must be green for the PR to be mergeable.

## Style notes

- `ruff` lint rules enabled: `E, F, W, I, N, UP, B, A, C4, SIM, ARG, PTH, ERA, PL, RUF` (see `pyproject.toml::[tool.ruff.lint]`).
- Line length: 120.
- Target Python: 3.14 (`target-version = "py314"` for ruff, `python-version = "3.14"` for ty).
- Async code should use `aiohttp` — never block the event loop.
- Every DPI probe's exception handling funnels through `diagnostics/error_classifier.classify()` so failure modes stay in the stable `ErrorLabel` taxonomy.

## Attribution

- Tier 1–6 DPI probes are ported from [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT).
- `scan` replicates the domain-censorship heuristics of [@tracerlab](https://t.me/tracerlab)'s bash script.
- Bundled domain lists — see `src/xray_analyzer/data/CREDITS.md` for sources ([hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist), [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains)).
- The Xray Checker API is provided by [kutovoy/xray-checker](https://github.com/kutovoy/xray-checker).

## License

MIT.
