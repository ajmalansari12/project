"""Sentinel-EDR Backend Application Entry Point.

Initializes the FastAPI application, settings, structured logging,
and lifecycle management.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from uuid import uuid4

from fastapi import FastAPI, Request

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.errors import register_error_handlers
from app.api.routes import api_router
from app.core.config import Settings, get_settings
from app.core.logging_config import setup_logging
from app.db.session import reset_database_engine
from app.services.analysis_worker import AnalysisWorkerManager, get_default_worker_manager


class RequestIdMiddleware:
    """Pure ASGI middleware attaching a correlation request_id to scope and response headers."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = MutableHeaders(scope=scope)
        request_id = headers.get("x-request-id") or str(uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                res_headers = MutableHeaders(scope=message)
                res_headers["x-request-id"] = request_id
            await send(message)

        await self.app(scope, receive, send_wrapper)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle events."""
    settings = getattr(app.state, "settings", None) or get_settings()
    logger = setup_logging(settings.log_level)
    logger.info(
        "Sentinel-EDR backend starting [version=%s, env=%s, debug=%s]",
        settings.app_version,
        settings.environment,
        settings.debug,
    )

    worker_manager: AnalysisWorkerManager | None = None
    if settings.analysis_workers_enabled:
        worker_manager = get_default_worker_manager()
        worker_manager.start(recover_interrupted=settings.analysis_recover_interrupted_on_startup)
        app.state.analysis_worker_manager = worker_manager

    if settings.yara_enabled:
        from app.services.yara_scanner import get_default_yara_scanner
        try:
            yara_scanner = get_default_yara_scanner()
            compiled_count = yara_scanner.load_rules(rules_dir=settings.yara_rules_dir)
            logger.info("YARA signature scanner initialized on startup [%d rule file(s) compiled]", compiled_count)
        except Exception as exc:
            logger.warning("Could not compile YARA rules on startup: %s", exc)

    if settings.ml_enabled:
        from app.services.onnx_inference_service import get_default_onnx_inference_service
        try:
            ml_service = get_default_onnx_inference_service()
            logger.info(
                "Static PE ML classifier initialized on startup [model_id=%s, version=%s, threshold=%.4f]",
                ml_service.model_id,
                ml_service.model_version,
                ml_service.threshold,
            )
        except Exception as exc:
            logger.warning("Could not load static PE ML model on startup: %s", exc)

    yield

    if worker_manager and worker_manager.is_running:
        worker_manager.stop()

    from app.services.onnx_inference_service import reset_default_onnx_inference_service
    reset_default_onnx_inference_service()

    reset_database_engine()
    logger.info("Sentinel-EDR backend shutting down cleanly.")


def create_application(settings: Settings | None = None) -> FastAPI:
    """Factory to create and configure the FastAPI application instance."""
    app_settings = settings or get_settings()
    setup_logging(app_settings.log_level)

    application = FastAPI(
        title=app_settings.app_name,
        version=app_settings.app_version,
        debug=app_settings.debug,
        lifespan=lifespan,
    )
    application.state.settings = app_settings

    # Attach pure ASGI request ID correlation middleware
    application.add_middleware(RequestIdMiddleware)

    # Mount API v1 endpoints
    application.include_router(api_router, prefix="/api/v1")

    # Attach domain and standard error handlers
    register_error_handlers(application)

    return application


# Global application instance for ASGI servers (e.g., Uvicorn)
app = create_application()
