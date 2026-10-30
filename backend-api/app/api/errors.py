"""Standardized API exception handlers formatting errors according to api_spec.md."""

import logging
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.contracts import ApiErrorDetail, ApiErrorResponse
from app.services.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    ResourceNotFoundError,
    ValidationError as ServiceValidationError,
)

logger = logging.getLogger("sentinel.api.errors")


def _resolve_request_id(request: Request) -> str:
    """Retrieve existing request correlation ID or generate a new fallback."""
    return getattr(request.state, "request_id", None) or str(uuid4())


def _create_error_response(
    status_code: int,
    code: str,
    message: str,
    request: Request,
    details: object = None,
) -> JSONResponse:
    """Construct an HTTP response with a validated ApiErrorResponse envelope."""
    request_id = _resolve_request_id(request)
    envelope = ApiErrorResponse(
        error=ApiErrorDetail(
            code=code,
            message=message,
            details=details if details is not None else {},
            request_id=request_id,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=envelope.model_dump(),
        headers={"X-Request-ID": request_id},
    )


async def resource_not_found_handler(request: Request, exc: ResourceNotFoundError) -> JSONResponse:
    """Handle service-level missing resource lookups as HTTP 404."""
    logger.info("Resource not found: %s [%s]", exc.resource_type, exc.resource_id)
    return _create_error_response(
        status_code=404,
        code="RESOURCE_NOT_FOUND",
        message=str(exc),
        request=request,
        details={"resource_type": exc.resource_type, "resource_id": exc.resource_id},
    )


async def persistence_conflict_handler(request: Request, exc: PersistenceConflictError) -> JSONResponse:
    """Handle database unique constraint or primary key collision conflicts as HTTP 409."""
    logger.warning("Persistence conflict: %s", exc)
    details = {}
    if exc.conflict_key:
        details["conflict_key"] = exc.conflict_key
    if exc.conflict_value:
        details["conflict_value"] = exc.conflict_value
    return _create_error_response(
        status_code=409,
        code="CONFLICT",
        message=str(exc),
        request=request,
        details=details,
    )


async def invalid_state_transition_handler(request: Request, exc: InvalidStateTransitionError) -> JSONResponse:
    """Handle illegal entity state machine transitions as HTTP 409."""
    logger.warning(
        "Invalid state transition on %s %s: '%s' -> '%s'",
        exc.resource_type,
        exc.resource_id,
        exc.current_status,
        exc.attempted_status,
    )
    return _create_error_response(
        status_code=409,
        code="INVALID_STATE_TRANSITION",
        message=str(exc),
        request=request,
        details={
            "resource_type": exc.resource_type,
            "resource_id": exc.resource_id,
            "current_status": exc.current_status,
            "attempted_status": exc.attempted_status,
        },
    )


async def service_validation_handler(request: Request, exc: ServiceValidationError) -> JSONResponse:
    """Handle domain validation errors as HTTP 422."""
    logger.info("Service validation error on field '%s': %s", exc.field, exc)
    details = {"field": exc.field} if exc.field else {}
    return _create_error_response(
        status_code=422,
        code="VALIDATION_ERROR",
        message=str(exc),
        request=request,
        details=details,
    )


async def request_validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle FastAPI and Pydantic request body/query validation errors as HTTP 422."""
    logger.info("Request validation failed on %s %s: %s", request.method, request.url.path, exc)
    errors = [
        {
            "loc": [str(loc) for loc in err.get("loc", [])],
            "msg": err.get("msg"),
            "type": err.get("type"),
        }
        for err in exc.errors()
    ]
    return _create_error_response(
        status_code=422,
        code="VALIDATION_ERROR",
        message="Request validation failed.",
        request=request,
        details={"errors": errors},
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle standard Starlette/FastAPI HTTP exceptions with consistent error envelope."""
    code = "RESOURCE_NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
    return _create_error_response(
        status_code=exc.status_code,
        code=code,
        message=str(exc.detail),
        request=request,
        details={},
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle uncaught server errors without leaking credentials or internal stack traces."""
    logger.exception("Unhandled server exception processing request %s: %s", request.url.path, exc)
    return _create_error_response(
        status_code=500,
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected internal server error occurred.",
        request=request,
        details={},
    )


def register_error_handlers(app: FastAPI) -> None:
    """Attach domain and standard exception handlers to the FastAPI application."""
    app.add_exception_handler(ResourceNotFoundError, resource_not_found_handler)  # type: ignore[arg-type]
    app.add_exception_handler(PersistenceConflictError, persistence_conflict_handler)  # type: ignore[arg-type]
    app.add_exception_handler(InvalidStateTransitionError, invalid_state_transition_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ServiceValidationError, service_validation_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, request_validation_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(500, unhandled_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
