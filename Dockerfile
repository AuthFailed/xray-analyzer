FROM python:3.14-slim AS base

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency файлы
COPY pyproject.toml uv.lock ./

# Install dependencies only (no dev)
RUN uv sync --frozen --no-install-project --no-dev

# Copy project files
COPY src/ src/
COPY README.md ./

# Install the project itself
RUN uv sync --frozen --no-dev

# Create logs and xray data directories
RUN mkdir -p /app/logs /app/xray-bin

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Default: run analysis
CMD ["uv", "run", "xray-analyzer", "analyze", "--watch"]
