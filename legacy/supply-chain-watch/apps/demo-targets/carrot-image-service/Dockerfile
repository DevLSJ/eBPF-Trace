# syntax=docker/dockerfile:1
# 빌드 컨텍스트는 저장소 루트(compose에서 지정). 오염 데모 패키지를 vendor/로 함께 담는다.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY packages/demo-packages/img-optimize-demo ./vendor/img-optimize-demo
COPY apps/demo-targets/carrot-image-service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY apps/demo-targets/carrot-image-service/app ./app
RUN useradd --system --uid 10001 app && mkdir -p /data/uploads && chown -R app /data
USER app
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
