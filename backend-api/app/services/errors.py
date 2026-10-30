"""Service-level exception hierarchy for Sentinel-EDR persistence layer.

These exceptions isolate domain and persistence errors from HTTP transport concerns.
"""

from typing import Any, Dict, Optional


class PersistenceError(Exception):
    """Base exception for all persistence and domain service operations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ResourceNotFoundError(PersistenceError):
    """Raised when a requested resource does not exist in the database."""

    def __init__(self, resource_type: str, resource_id: str) -> None:
        message = f"{resource_type} with ID '{resource_id}' not found."
        super().__init__(message, {"resource_type": resource_type, "resource_id": resource_id})
        self.resource_type = resource_type
        self.resource_id = resource_id


class PersistenceConflictError(PersistenceError):
    """Raised when an operation violates unique constraints or primary key uniqueness."""

    def __init__(
        self,
        message: str,
        conflict_key: Optional[str] = None,
        conflict_value: Optional[str] = None,
    ) -> None:
        details = {}
        if conflict_key:
            details["conflict_key"] = conflict_key
        if conflict_value:
            details["conflict_value"] = conflict_value
        super().__init__(message, details)
        self.conflict_key = conflict_key
        self.conflict_value = conflict_value


class InvalidStateTransitionError(PersistenceError):
    """Raised when attempting an illegal state transition according to the documented lifecycle."""

    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        current_state: str,
        target_state: str,
        message: Optional[str] = None,
    ) -> None:
        msg = message or (
            f"Invalid state transition for {resource_type} '{resource_id}': "
            f"cannot transition from '{current_state}' to '{target_state}'."
        )
        super().__init__(
            msg,
            {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "current_state": current_state,
                "target_state": target_state,
            },
        )
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.current_state = current_state
        self.target_state = target_state


class ValidationError(PersistenceError):
    """Raised when service-level domain validation fails before or during persistence."""

    def __init__(self, message: str, field: Optional[str] = None) -> None:
        details = {"field": field} if field else {}
        super().__init__(message, details)
        self.field = field
