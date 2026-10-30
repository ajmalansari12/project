"""System component status endpoint evaluating backend subsystem availability."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from app.db.session import get_default_engine
from app.schemas.api import ComponentStatusMap, StatusResponse
from app.schemas.contracts import ComponentAvailability

logger = logging.getLogger("sentinel.api.status")
router = APIRouter(tags=["Status"])


def _check_database_availability() -> ComponentAvailability:
    """Verify relational database connectivity."""
    try:
        engine = get_default_engine()
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return ComponentAvailability.AVAILABLE
    except Exception as exc:
        logger.warning(
            "Database connectivity check failed: %s",
            type(exc).__name__,
        )
        return ComponentAvailability.UNAVAILABLE


def _check_signature_engine_availability() -> ComponentAvailability:
    """Evaluate operational status of the YARA signature engine."""

    from app.services.yara_scanner import _default_scanner

    if _default_scanner is None:
        return ComponentAvailability.NOT_INITIALIZED

    from app.core.config import get_settings
    settings = get_settings()

    if not settings.yara_enabled:
        return ComponentAvailability.DISABLED

    if _default_scanner.is_ready:
        return ComponentAvailability.AVAILABLE

    return ComponentAvailability.UNAVAILABLE


def _check_ml_engine_availability() -> ComponentAvailability:
    """Evaluate operational status of the static PE ML inference engine."""

    from app.services.onnx_inference_service import _default_inference_service

    if _default_inference_service is None:
        return ComponentAvailability.NOT_INITIALIZED

    from app.core.config import get_settings
    settings = get_settings()

    if not settings.ml_enabled:
        return ComponentAvailability.DISABLED

    if (
        _default_inference_service.is_loaded
        and _default_inference_service.health_status.value == "healthy"
    ):
        return ComponentAvailability.AVAILABLE

    if _default_inference_service.health_status.value == "degraded":
        return ComponentAvailability.DEGRADED

    return ComponentAvailability.UNAVAILABLE


@router.get(
    "/status",
    response_model=StatusResponse,
    summary="Get Component Status",
    description="Observational endpoint reporting the actual operational availability of backend components.",
)
def get_system_status() -> StatusResponse:
    """Report real-time availability of backend components."""

    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    db_status = _check_database_availability()
    sig_status = _check_signature_engine_availability()
    ml_status = _check_ml_engine_availability()

    components = ComponentStatusMap(
        database=db_status,
        signature_engine=sig_status,
        ml_engine=ml_status,
        behavioral_monitor=ComponentAvailability.NOT_INITIALIZED,
        ai_reporting=ComponentAvailability.NOT_INITIALIZED,
    )

    if db_status == ComponentAvailability.AVAILABLE:
        overall_status = "degraded"
    else:
        overall_status = "unavailable"

    return StatusResponse(
        status=overall_status,
        components=components,
        timestamp=now_utc,
    )
