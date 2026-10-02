# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS base
WORKDIR /app
COPY apps/engine/pyproject.toml apps/engine/uv.lock* ./
RUN uv sync --no-dev --no-install-project
COPY apps/engine/ ./
RUN uv sync --no-dev
EXPOSE 8000
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
