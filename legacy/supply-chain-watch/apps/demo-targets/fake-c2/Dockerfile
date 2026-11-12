# syntax=docker/dockerfile:1
FROM python:3.12-alpine
WORKDIR /app
COPY server.py ./
USER nobody
EXPOSE 9001
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD wget -qO- http://127.0.0.1:9001/health >/dev/null || exit 1
CMD ["python", "-u", "server.py"]
