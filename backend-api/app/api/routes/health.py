"""Health check API route reporting API liveness."""

from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.api import HealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Check API Health",
    description="Reports whether the FastAPI application process is active and responsive.",
)
def get_health() -> HealthResponse:
    """Check API process liveness without evaluating database or detection dependencies."""
    settings = get_settings()
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return HealthResponse(
        status="healthy",
        service="sentinel-edr-api",
        version=settings.app_version,
        timestamp=now_utc,
    )
