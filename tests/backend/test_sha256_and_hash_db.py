"""Automated tests for SHA-256 chunked hashing and local hash reputation database service."""

import hashlib
import os
from pathlib import Path
import tempfile
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.session import create_database_engine, get_session_factory
from app.models.hash_reputation import HashReputation
from app.schemas.contracts import (
    HashListType,
    SecurityVerdict,
)
from app.services.errors import (
    PersistenceConflictError,
    ValidationError,
)
import app.services.hash_database_service as hash_db_mod
from app.services.hash_database_service import (
    HashLookupResult,
    create_hash_reputation,
    delete_hash_reputation,
    get_hash_reputation,
    list_hash_reputations,
    lookup_hash,
    upsert_hash_reputation,
)
from app.services.sha256_service import (
    DEFAULT_CHUNK_SIZE,
    EMPTY_FILE_SHA256,
    compute_bytes_sha256,
    compute_file_sha256,
    is_valid_sha256,
    normalize_sha256,
)


@pytest.fixture
def memory_db_session():
    """Create an isolated in-memory SQLite database session with foreign keys."""
    engine = create_database_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


# ==============================================================================
# 1. SHA-256 Service Tests
# ==============================================================================

def test_sha256_empty_file():
    """Verify empty file yields the canonical NIST SHA-256 digest."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf_path = Path(tf.name)
    try:
        digest = compute_file_sha256(tf_path)
        assert digest == EMPTY_FILE_SHA256
        assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_sha256_known_test_vectors():
    """Verify standard NIST test vectors produce deterministic lowercase digests."""
    # Vector 1: "abc"
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"abc")
        tf_path = Path(tf.name)
    try:
        digest = compute_file_sha256(tf_path)
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert digest == expected
        assert compute_bytes_sha256(b"abc") == expected
    finally:
        if tf_path.exists():
            tf_path.unlink()

    # Vector 2: 56-byte string
    msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(msg)
        tf_path2 = Path(tf.name)
    try:
        digest2 = compute_file_sha256(tf_path2)
        expected2 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        assert digest2 == expected2
        assert compute_bytes_sha256(msg) == expected2
    finally:
        if tf_path2.exists():
            tf_path2.unlink()


def test_sha256_chunked_streaming_consistency():
    """Verify chunked reading produces identical results across different chunk sizes."""
    payload = b"Sentinel-EDR Security Payload \x00\xff\xfe" * 5000  # ~175 KB
    expected = hashlib.sha256(payload).hexdigest().lower()

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(payload)
        tf_path = Path(tf.name)
    try:
        # Default chunk size (64KB)
        assert compute_file_sha256(tf_path) == expected
        # Small chunk sizes forcing multiple iterations
        assert compute_file_sha256(tf_path, chunk_size=1024) == expected
        assert compute_file_sha256(tf_path, chunk_size=37) == expected
        assert compute_file_sha256(tf_path, chunk_size=1) == expected
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_sha256_invalid_chunk_size():
    """Verify non-positive chunk size raises ValueError."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"data")
        tf_path = Path(tf.name)
    try:
        with pytest.raises(ValueError, match="chunk_size must be a positive integer"):
            compute_file_sha256(tf_path, chunk_size=0)
        with pytest.raises(ValueError, match="chunk_size must be a positive integer"):
            compute_file_sha256(tf_path, chunk_size=-100)
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_sha256_nonexistent_file_raises_not_found():
    """Verify missing file raises FileNotFoundError without returning partial hash."""
    fake_path = Path(tempfile.gettempdir()) / f"non_existent_{uuid4().hex}.bin"
    assert not fake_path.exists()
    with pytest.raises(FileNotFoundError, match="Target file does not exist"):
        compute_file_sha256(fake_path)


def test_sha256_directory_raises_is_a_directory():
    """Verify directory path raises IsADirectoryError."""
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises(IsADirectoryError, match="Target path is a directory"):
            compute_file_sha256(td)


def test_sha256_validation_and_normalization():
    """Verify validation and normalization of SHA-256 digests."""
    raw_valid = "Ba7816Bf8F01CfEa414140De5DaE2223b00361a396177a9cb410ff61f20015ad"
    normalized = normalize_sha256(raw_valid)
    assert normalized == raw_valid.lower()
    assert is_valid_sha256(raw_valid) is True
    assert is_valid_sha256(normalized) is True

    # Whitespace trimming
    assert normalize_sha256(f"  {raw_valid}  \n") == raw_valid.lower()

    # Rejection of invalid inputs
    with pytest.raises(ValidationError, match="Invalid SHA-256 hash digest"):
        normalize_sha256("too_short")

    with pytest.raises(ValidationError, match="Invalid SHA-256 hash digest"):
        normalize_sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015az")  # non-hex 'z'

    with pytest.raises(ValidationError, match="file_hash is required"):
        normalize_sha256("")

    assert is_valid_sha256("not_a_hash") is False
    assert is_valid_sha256("") is False
    assert is_valid_sha256(None) is False


# ==============================================================================
# 2. Hash Database Service Tests
# ==============================================================================

def test_hash_database_lookup_unknown_hash_is_not_benign(memory_db_session: Session):
    """Verify querying an unrecorded hash returns is_known=False and verdict=None.

    CRITICAL: Never classify unknown hashes automatically as benign.
    """
    unknown_hash = "1" * 64
    result = lookup_hash(memory_db_session, unknown_hash)

    assert isinstance(result, HashLookupResult)
    assert result.file_hash == unknown_hash
    assert result.is_known is False
    assert result.verdict is None
    assert result.list_type is None
    assert result.description is None
    assert result.source is None
    assert result.metadata is None
    assert result.matched_at is None


def test_hash_database_create_and_lookup_match(memory_db_session: Session):
    """Verify persisting a known hash allows case-insensitive retrieval of reputation metadata."""
    stored_hash = "abcdef0123456789" * 4
    metadata = {"category": "known_malware", "source_feed": "cert_alert_2026"}

    created = create_hash_reputation(
        memory_db_session,
        file_hash=stored_hash,
        verdict=SecurityVerdict.MALICIOUS,
        list_type=HashListType.BLOCKLIST,
        description="Ransomware dropper variant",
        source="threat_feed_a",
        metadata=metadata,
    )
    assert created.reputation_id is not None
    assert created.file_hash == stored_hash
    assert created.verdict == "MALICIOUS"
    assert created.list_type == "BLOCKLIST"

    # Query using uppercase representation
    lookup = lookup_hash(memory_db_session, stored_hash.upper())
    assert lookup.is_known is True
    assert lookup.verdict == SecurityVerdict.MALICIOUS
    assert lookup.list_type == HashListType.BLOCKLIST
    assert lookup.description == "Ransomware dropper variant"
    assert lookup.source == "threat_feed_a"
    assert lookup.metadata == metadata
    assert lookup.matched_at is not None


def test_service_stores_uppercase_input_as_canonical_lowercase(memory_db_session: Session):
    """Verify application service normalizes uppercase inputs and persists only lowercase."""
    raw_upper = "ABCDEF" + "0" * 58
    expected_lower = raw_upper.lower()

    created = create_hash_reputation(
        memory_db_session,
        file_hash=raw_upper,
        verdict=SecurityVerdict.BENIGN,
        list_type=HashListType.ALLOWLIST,
        description="System binary allowlist entry",
    )
    assert created.file_hash == expected_lower

    # Verify actual stored representation in database
    row = memory_db_session.execute(
        text("SELECT file_hash FROM hash_reputations WHERE reputation_id = :id"),
        {"id": created.reputation_id},
    ).scalar_one()
    assert row == expected_lower


def test_lookup_case_insensitivity(memory_db_session: Session):
    """Verify lookup resolves correctly with uppercase, lowercase, and mixed-case queries."""
    sample_hash = "deadbeef" * 8
    create_hash_reputation(
        memory_db_session,
        file_hash=sample_hash,
        verdict=SecurityVerdict.SUSPICIOUS,
        list_type=HashListType.CUSTOM,
    )

    # Lowercase query
    res_lower = lookup_hash(memory_db_session, sample_hash.lower())
    assert res_lower.is_known is True
    assert res_lower.file_hash == sample_hash.lower()

    # Uppercase query
    res_upper = lookup_hash(memory_db_session, sample_hash.upper())
    assert res_upper.is_known is True
    assert res_upper.file_hash == sample_hash.lower()

    # Mixed-case query
    mixed = sample_hash[:32].upper() + sample_hash[32:].lower()
    res_mixed = lookup_hash(memory_db_session, mixed)
    assert res_mixed.is_known is True
    assert res_mixed.file_hash == sample_hash.lower()


def test_duplicate_digests_prevented_through_case_variation(memory_db_session: Session):
    """Verify duplicate digests cannot be stored through case variation."""
    sample_hash = "a1b2c3d4" * 8
    create_hash_reputation(
        memory_db_session,
        file_hash=sample_hash.lower(),
        verdict=SecurityVerdict.BENIGN,
        list_type=HashListType.ALLOWLIST,
    )

    # Attempting to store uppercase version of the same hash must fail with PersistenceConflictError
    with pytest.raises(PersistenceConflictError) as exc_info:
        create_hash_reputation(
            memory_db_session,
            file_hash=sample_hash.upper(),
            verdict=SecurityVerdict.MALICIOUS,
            list_type=HashListType.BLOCKLIST,
        )
    assert exc_info.value.conflict_key == "file_hash"
    assert exc_info.value.conflict_value == sample_hash.lower()


def test_direct_db_insert_uppercase_violates_constraint(memory_db_session: Session):
    """Verify direct DB insert with uppercase characters violates the check constraint."""
    rep_id = str(uuid4())
    uppercase_hash = "A" * 64
    now = "2026-10-29T12:00:00Z"

    with pytest.raises(IntegrityError):
        memory_db_session.execute(
            text(
                "INSERT INTO hash_reputations (reputation_id, file_hash, verdict, list_type, source, created_at, updated_at) "
                "VALUES (:id, :file_hash, 'BENIGN', 'ALLOWLIST', 'test', :now, :now)"
            ),
            {"id": rep_id, "file_hash": uppercase_hash, "now": now},
        )
        memory_db_session.flush()


def test_direct_db_insert_non_hex_violates_constraint(memory_db_session: Session):
    """Verify direct DB insert with non-hex characters violates the check constraint."""
    rep_id = str(uuid4())
    non_hex_hash = "0" * 63 + "g"
    now = "2026-10-29T12:00:00Z"

    with pytest.raises(IntegrityError):
        memory_db_session.execute(
            text(
                "INSERT INTO hash_reputations (reputation_id, file_hash, verdict, list_type, source, created_at, updated_at) "
                "VALUES (:id, :file_hash, 'BENIGN', 'ALLOWLIST', 'test', :now, :now)"
            ),
            {"id": rep_id, "file_hash": non_hex_hash, "now": now},
        )
        memory_db_session.flush()


def test_direct_db_insert_invalid_length_violates_constraint(memory_db_session: Session):
    """Verify direct DB insert with length != 64 violates the check constraint."""
    rep_id = str(uuid4())
    short_hash = "a" * 63
    now = "2026-10-29T12:00:00Z"

    with pytest.raises(IntegrityError):
        memory_db_session.execute(
            text(
                "INSERT INTO hash_reputations (reputation_id, file_hash, verdict, list_type, source, created_at, updated_at) "
                "VALUES (:id, :file_hash, 'BENIGN', 'ALLOWLIST', 'test', :now, :now)"
            ),
            {"id": rep_id, "file_hash": short_hash, "now": now},
        )
        memory_db_session.flush()


def test_hash_database_duplicate_hash_conflict_error(memory_db_session: Session):
    """Verify inserting duplicate file_hash raises PersistenceConflictError."""
    sample_hash = "2" * 64
    create_hash_reputation(
        memory_db_session,
        file_hash=sample_hash,
        verdict=SecurityVerdict.BENIGN,
        list_type=HashListType.ALLOWLIST,
    )

    with pytest.raises(PersistenceConflictError) as exc_info:
        create_hash_reputation(
            memory_db_session,
            file_hash=sample_hash,
            verdict=SecurityVerdict.MALICIOUS,
            list_type=HashListType.BLOCKLIST,
        )
    assert exc_info.value.conflict_key == "file_hash"
    assert exc_info.value.conflict_value == sample_hash


def test_hash_database_upsert_functionality(memory_db_session: Session):
    """Verify upsert creates missing record and updates existing record in place."""
    sample_hash = "3" * 64

    # 1. First upsert creates entry
    rec1 = upsert_hash_reputation(
        memory_db_session,
        file_hash=sample_hash,
        verdict=SecurityVerdict.SUSPICIOUS,
        list_type=HashListType.CUSTOM,
        description="Initial observation",
        source="analyst_notes",
    )
    assert rec1.verdict == "SUSPICIOUS"
    assert rec1.list_type == "CUSTOM"

    # 2. Second upsert updates existing entry
    rec2 = upsert_hash_reputation(
        memory_db_session,
        file_hash=sample_hash,
        verdict=SecurityVerdict.MALICIOUS,
        list_type=HashListType.BLOCKLIST,
        description="Confirmed malicious payload",
        source="virustotal",
    )
    assert rec2.reputation_id == rec1.reputation_id
    assert rec2.verdict == "MALICIOUS"
    assert rec2.list_type == "BLOCKLIST"
    assert rec2.description == "Confirmed malicious payload"
    assert rec2.source == "virustotal"


def test_hash_database_validation_rejects_invalid_inputs(memory_db_session: Session):
    """Verify validation errors on malformed hash, invalid verdict, or empty source."""
    valid_hash = "4" * 64

    # Invalid hash length
    with pytest.raises(ValidationError, match="Invalid SHA-256 hash digest"):
        create_hash_reputation(
            memory_db_session,
            file_hash="1234",
            verdict=SecurityVerdict.BENIGN,
            list_type=HashListType.ALLOWLIST,
        )

    # Invalid verdict
    with pytest.raises(ValidationError, match="Invalid verdict"):
        create_hash_reputation(
            memory_db_session,
            file_hash=valid_hash,
            verdict="UNKNOWN_VERDICT",
            list_type=HashListType.ALLOWLIST,
        )

    # Invalid list type
    with pytest.raises(ValidationError, match="Invalid list_type"):
        create_hash_reputation(
            memory_db_session,
            file_hash=valid_hash,
            verdict=SecurityVerdict.BENIGN,
            list_type="GLOBAL_LIST",
        )

    # Empty source
    with pytest.raises(ValidationError, match="source is required"):
        create_hash_reputation(
            memory_db_session,
            file_hash=valid_hash,
            verdict=SecurityVerdict.BENIGN,
            list_type=HashListType.ALLOWLIST,
            source="   ",
        )


def test_hash_database_listing_and_filtering(memory_db_session: Session):
    """Verify paginated listing with verdict and list_type filtering."""
    # Seed 5 records
    hashes = [f"{i:02x}" * 32 for i in range(1, 6)]
    create_hash_reputation(
        memory_db_session, file_hash=hashes[0], verdict=SecurityVerdict.BENIGN, list_type=HashListType.ALLOWLIST
    )
    create_hash_reputation(
        memory_db_session, file_hash=hashes[1], verdict=SecurityVerdict.BENIGN, list_type=HashListType.ALLOWLIST
    )
    create_hash_reputation(
        memory_db_session, file_hash=hashes[2], verdict=SecurityVerdict.MALICIOUS, list_type=HashListType.BLOCKLIST
    )
    create_hash_reputation(
        memory_db_session, file_hash=hashes[3], verdict=SecurityVerdict.MALICIOUS, list_type=HashListType.BLOCKLIST
    )
    create_hash_reputation(
        memory_db_session, file_hash=hashes[4], verdict=SecurityVerdict.SUSPICIOUS, list_type=HashListType.CUSTOM
    )

    # Total list
    res_all = list_hash_reputations(memory_db_session, page=1, page_size=10)
    assert res_all.total_items == 5
    assert len(res_all.items) == 5

    # Filter by verdict
    res_mal = list_hash_reputations(memory_db_session, verdict="MALICIOUS")
    assert res_mal.total_items == 2
    assert all(r.verdict == "MALICIOUS" for r in res_mal.items)

    # Filter by list_type
    res_allow = list_hash_reputations(memory_db_session, list_type="ALLOWLIST")
    assert res_allow.total_items == 2
    assert all(r.list_type == "ALLOWLIST" for r in res_allow.items)


def test_hash_database_delete(memory_db_session: Session):
    """Verify deleting a hash reputation entry."""
    sample_hash = "5" * 64
    create_hash_reputation(
        memory_db_session,
        file_hash=sample_hash,
        verdict=SecurityVerdict.BENIGN,
        list_type=HashListType.ALLOWLIST,
    )

    assert delete_hash_reputation(memory_db_session, sample_hash) is True
    assert get_hash_reputation(memory_db_session, sample_hash) is None
    assert delete_hash_reputation(memory_db_session, sample_hash) is False


def test_caller_controlled_transaction_semantics(memory_db_session: Session):
    """Verify hash database operations flush without committing the outer session."""
    sample_hash = "7" * 64
    create_hash_reputation(
        memory_db_session,
        file_hash=sample_hash,
        verdict=SecurityVerdict.BENIGN,
        list_type=HashListType.ALLOWLIST,
    )

    # Roll back the session
    memory_db_session.rollback()

    # The record should not exist after rollback
    assert get_hash_reputation(memory_db_session, sample_hash) is None


def test_no_premature_detection_evidence_scoring_in_t008():
    """Verify build_hash_detection_evidence was removed to prevent premature scoring in T008."""
    assert not hasattr(hash_db_mod, "build_hash_detection_evidence")
    import app.services as srv
    assert not hasattr(srv, "build_hash_detection_evidence")
