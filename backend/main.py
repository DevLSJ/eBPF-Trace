import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from starlette.exceptions import HTTPException

from backend.api.routes import router as api_router
from backend.core.config import Settings
from backend.core.schemas import Thresholds
from backend.db.database import Database
from backend.db.models import Base, RuntimeConfig
from backend.services.metrics_collector import collect_metrics
from backend.websocket.collector import router as ws_router
from backend.websocket.manager import ConnectionManager
from ml.engine import DetectionEngine


def create_app(settings: Settings | None = None):
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        logging.basicConfig(level=settings.log_level)
        app.state.settings = settings
        app.state.db = Database(settings.database_url)
        app.state.redis = Redis.from_url(
            settings.redis_url, socket_connect_timeout=1, socket_timeout=1
        )
        app.state.redis_available = False
        app.state.collector_connections = 0
        app.state.alert_tasks = set()
        app.state.manager = ConnectionManager()
        app.state.detector = DetectionEngine(settings.model_path, settings.scaler_path)
        if settings.auto_create_schema:
            async with app.state.db.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        async with app.state.db.sessions() as session:
            config = await session.get(RuntimeConfig, 1)
            if config:
                app.state.detector.rules.thresholds = Thresholds(**config.thresholds)
        task = asyncio.create_task(collect_metrics(app)) if settings.metrics_enabled else None
        try:
            yield
        finally:
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await app.state.manager.close()
            if app.state.alert_tasks:
                await asyncio.gather(*app.state.alert_tasks, return_exceptions=True)
            await app.state.redis.aclose()
            await app.state.db.engine.dispose()

    app = FastAPI(title="eBPF Trace", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins.split(","),
        allow_methods=["GET", "PUT"],
        allow_headers=["Authorization", "Content-Type"],
    )

    def error_response(status, code, message):
        return JSONResponse(
            status_code=status,
            content={
                "error": {
                    "code": code,
                    "message": message,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            },
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error):
        return error_response(
            error.status_code,
            {400: "BAD_REQUEST", 401: "UNAUTHORIZED", 404: "NOT_FOUND", 503: "UNAVAILABLE"}.get(
                error.status_code, "HTTP_ERROR"
            ),
            str(error.detail),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error):
        return error_response(
            422, "VALIDATION_ERROR", "; ".join(item["msg"] for item in error.errors())
        )

    @app.exception_handler(Exception)
    async def server_error(request: Request, error):
        logging.getLogger(__name__).error("Unhandled request error", exc_info=error)
        return error_response(500, "INTERNAL_ERROR", "An internal error occurred")

    app.include_router(api_router)
    app.include_router(ws_router)
    return app


app = create_app()
