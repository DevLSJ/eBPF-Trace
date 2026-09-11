FROM python:3.14-slim AS builder
WORKDIR /build
COPY backend/requirements.txt requirements.txt
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.14-slim
RUN useradd --create-home --uid 10001 app
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY backend /app/backend
COPY ml /app/ml
COPY alembic.ini /app/alembic.ini
USER app
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 1 --ws-max-size 65536"]
