"""Persistence and lookup service for local SHA-256 hash reputation lists.

Provides caller-managed transactional lookups, insertions, updates, and evidence
normalization for local allowlists, blocklists, and custom reputation entries.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.hash_reputation import HashReputation
from app.schemas.contracts import HashListType, SecurityVerdict
from app.services.common import PaginatedResult, deserialize_json, paginate_query, serialize_json, utc_now_iso
from app.services.errors import PersistenceConflictError, PersistenceError, ValidationError
from app.services.sha256_service import normalize_sha256

VALID_VERDICTS = {v.value for v in SecurityVerdict}
VALID_LIST_TYPES = {lt.value for lt in HashListType}


@dataclass(frozen=True)
class HashLookupResult:
    """Structured result of a hash reputation query against the local database.

    Explicitly models non-matches with is_known=False and verdict=None.
    An unknown hash is never treated as benign.
    """

    file_hash: str
    is_known: bool
    verdict: Optional[SecurityVerdict] = None
    list_type: Optional[HashListType] = None
    description: Optional[str] = None
    source: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    matched_at: Optional[str] = None


def lookup_hash(
    session: Session,
    file_hash: str,
) -> HashLookupResult:
    """Look up a file hash in the local hash reputation database.

    Normalizes the input hash to lowercase 64-character hexadecimal before querying.
    Non-matches return is_known=False and verdict=None.

    Args:
        session: Active SQLAlchemy database session.
        file_hash: 64-character SHA-256 hexadecimal digest string.

    Returns:
        HashLookupResult representing the query findings.

    Raises:
        ValidationError: If file_hash is invalid or malformed.
    """
    normalized_hash = normalize_sha256(file_hash)

    stmt = select(HashReputation).where(HashReputation.file_hash == normalized_hash)
    record = session.execute(stmt).scalar_one_or_none()

    if record is None:
        return HashLookupResult(
            file_hash=normalized_hash,
            is_known=False,
            verdict=None,
            list_type=None,
            description=None,
            source=None,
            metadata=None,
            matched_at=None,
        )

    return HashLookupResult(
        file_hash=record.file_hash,
        is_known=True,
        verdict=SecurityVerdict(record.verdict),
        list_type=HashListType(record.list_type),
        description=record.description,
        source=record.source,
        metadata=deserialize_json(record.metadata_json),
        matched_at=utc_now_iso(),
    )


def create_hash_reputation(
    session: Session,
    *,
    file_hash: str,
    verdict: Union[SecurityVerdict, str],
    list_type: Union[HashListType, str],
    description: Optional[str] = None,
    source: str = "local",
    metadata: Optional[Dict[str, Any]] = None,
    reputation_id: Optional[str] = None,
) -> HashReputation:
    """Create and persist a new hash reputation record.

    Validates format, verdict, and list_type constraints before persisting.

    Args:
        session: Active SQLAlchemy session (caller manages commits/rollbacks).
        file_hash: 64-character SHA-256 hexadecimal digest.
        verdict: Security verdict (BENIGN, SUSPICIOUS, or MALICIOUS).
        list_type: List classification (ALLOWLIST, BLOCKLIST, or CUSTOM).
        description: Optional human-readable description or rationale.
        source: Provenance indicator (default 'local').
        metadata: Optional structured supplementary metadata.
        reputation_id: Optional explicit UUID (generated if omitted).

    Returns:
        The newly created and flushed HashReputation model instance.

    Raises:
        ValidationError: If any argument fails validation.
        PersistenceConflictError: If a record with this file_hash already exists.
        PersistenceError: If database persistence fails.
    """
    normalized_hash = normalize_sha256(file_hash)

    verdict_str = verdict.value if isinstance(verdict, SecurityVerdict) else str(verdict)
    if verdict_str not in VALID_VERDICTS:
        raise ValidationError(
            f"Invalid verdict '{verdict_str}'. Allowed: {sorted(VALID_VERDICTS)}",
            field="verdict",
        )

    list_type_str = list_type.value if isinstance(list_type, HashListType) else str(list_type)
    if list_type_str not in VALID_LIST_TYPES:
        raise ValidationError(
            f"Invalid list_type '{list_type_str}'. Allowed: {sorted(VALID_LIST_TYPES)}",
            field="list_type",
        )

    if not source or not isinstance(source, str) or not source.strip():
        raise ValidationError("source is required and cannot be empty.", field="source")

    resolved_id = str(reputation_id or uuid4())
    now = utc_now_iso()

    record = HashReputation(
        reputation_id=resolved_id,
        file_hash=normalized_hash,
        verdict=verdict_str,
        list_type=list_type_str,
        description=description,
        source=source.strip(),
        metadata_json=serialize_json(metadata),
        created_at=now,
        updated_at=now,
    )

    try:
        session.add(record)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Hash reputation record with hash '{normalized_hash}' already exists.",
                conflict_key="file_hash",
                conflict_value=normalized_hash,
            ) from exc
        raise PersistenceError(f"Failed to persist hash reputation: {orig_msg}") from exc

    return record


def upsert_hash_reputation(
    session: Session,
    *,
    file_hash: str,
    verdict: Union[SecurityVerdict, str],
    list_type: Union[HashListType, str],
    description: Optional[str] = None,
    source: str = "local",
    metadata: Optional[Dict[str, Any]] = None,
) -> HashReputation:
    """Insert or update a hash reputation entry.

    If an entry for the given file_hash exists, updates its verdict, list_type,
    description, source, and metadata. Otherwise, creates a new entry.

    Returns:
        The updated or created HashReputation instance.
    """
    normalized_hash = normalize_sha256(file_hash)
    existing = get_hash_reputation(session, normalized_hash)

    if existing is None:
        return create_hash_reputation(
            session,
            file_hash=normalized_hash,
            verdict=verdict,
            list_type=list_type,
            description=description,
            source=source,
            metadata=metadata,
        )

    verdict_str = verdict.value if isinstance(verdict, SecurityVerdict) else str(verdict)
    if verdict_str not in VALID_VERDICTS:
        raise ValidationError(
            f"Invalid verdict '{verdict_str}'. Allowed: {sorted(VALID_VERDICTS)}",
            field="verdict",
        )

    list_type_str = list_type.value if isinstance(list_type, HashListType) else str(list_type)
    if list_type_str not in VALID_LIST_TYPES:
        raise ValidationError(
            f"Invalid list_type '{list_type_str}'. Allowed: {sorted(VALID_LIST_TYPES)}",
            field="list_type",
        )

    if not source or not isinstance(source, str) or not source.strip():
        raise ValidationError("source is required and cannot be empty.", field="source")

    existing.verdict = verdict_str
    existing.list_type = list_type_str
    existing.description = description
    existing.source = source.strip()
    existing.metadata_json = serialize_json(metadata)
    existing.updated_at = utc_now_iso()

    session.flush()
    return existing


def get_hash_reputation(
    session: Session,
    file_hash: str,
) -> Optional[HashReputation]:
    """Retrieve a single hash reputation record by its hash digest, or None if not found."""
    normalized_hash = normalize_sha256(file_hash)
    stmt = select(HashReputation).where(HashReputation.file_hash == normalized_hash)
    return session.execute(stmt).scalar_one_or_none()


def list_hash_reputations(
    session: Session,
    *,
    page: int = 1,
    page_size: int = 20,
    verdict: Optional[str] = None,
    list_type: Optional[str] = None,
    source: Optional[str] = None,
) -> PaginatedResult[HashReputation]:
    """Retrieve a paginated collection of hash reputations with optional filtering."""
    stmt = select(HashReputation)

    if verdict:
        if verdict not in VALID_VERDICTS:
            raise ValidationError(
                f"Invalid verdict filter '{verdict}'. Allowed: {sorted(VALID_VERDICTS)}",
                field="verdict",
            )
        stmt = stmt.where(HashReputation.verdict == verdict)

    if list_type:
        if list_type not in VALID_LIST_TYPES:
            raise ValidationError(
                f"Invalid list_type filter '{list_type}'. Allowed: {sorted(VALID_LIST_TYPES)}",
                field="list_type",
            )
        stmt = stmt.where(HashReputation.list_type == list_type)

    if source:
        stmt = stmt.where(HashReputation.source == source)

    stmt = stmt.order_by(HashReputation.created_at.desc(), HashReputation.reputation_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)


def delete_hash_reputation(
    session: Session,
    file_hash: str,
) -> bool:
    """Delete a hash reputation record by file hash.

    Returns:
        True if the record was deleted, False if no matching record existed.
    """
    record = get_hash_reputation(session, file_hash)
    if record is None:
        return False
    session.delete(record)
    session.flush()
    return True

