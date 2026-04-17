# Разработка

## Требования

- **Python ≥ 3.14**
- [`uv`](https://github.com/astral-sh/uv) — проект использует его для зависимостей и venv
- `git`, стандартный набор билд-тулов

```bash
git clone https://github.com/AuthFailed/xray-analyzer
cd xray-analyzer
uv sync --all-extras --dev
```

## Команды

```bash
# Полный прогон тестов
uv run pytest

# Один файл / один тест
uv run pytest tests/test_censor_checker.py
uv run pytest tests/test_censor_checker.py::TestIsRknSpoof::test_known_rkn_ip

# Линтер
uv run ruff check src/ tests/

# Форматирование
uv run ruff format src/ tests/

# Type check
uv run ty check

# Точка входа CLI (то же самое, что и в docker)
uv run xray-analyzer --help
```

## Соглашения по тестам

- Тесты лежат в `tests/`, по одному файлу на модуль (`tests/test_<module>.py`).
- `pytest-asyncio` работает в `auto`-режиме — каждый `async def test_*` автоматически считается асинхронным (`pyproject.toml::[tool.pytest.ini_options]::asyncio_mode = "auto"`).
- HTTP-мокинг через [`aioresponses`](https://github.com/pnuckowski/aioresponses) — живых сетевых вызовов в тестах нет.
- Сейчас 214 тестов; на типичном ноутбуке полный прогон — около 13 секунд.

## CI

`.github/workflows/ci.yml` запускается на каждый push / PR в `main`:

1. `uv sync --all-extras --dev`
2. `uv run ruff check src/ tests/`
3. `uv run ruff format --check src/ tests/`
4. `uv run ty check`
5. `uv run pytest`

Все пять шагов должны быть зелёными, чтобы PR можно было смерджить.

## Стиль кода

- Включённые правила `ruff`: `E, F, W, I, N, UP, B, A, C4, SIM, ARG, PTH, ERA, PL, RUF` (см. `pyproject.toml::[tool.ruff.lint]`).
- Длина строки: 120.
- Целевой Python: 3.14 (`target-version = "py314"` для ruff, `python-version = "3.14"` для ty).
- Асинхронный код — только `aiohttp`; event loop блокировать нельзя.
- Обработка исключений в каждой DPI-пробе прогоняется через `diagnostics/error_classifier.classify()`, чтобы режимы сбоя оставались в стабильной таксономии `ErrorLabel`.

## Благодарности

- Пробы Tier 1–6 адаптированы из [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT).
- Логика `scan` повторяет эвристики bash-скрипта [@tracerlab](https://t.me/tracerlab).
- Встроенные списки доменов — источники перечислены в `src/xray_analyzer/data/CREDITS.md` ([hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist), [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains)).
## Лицензия

MIT.
