"""Automated tests for Sentinel-EDR API foundation endpoints and error handling."""

from datetime import datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.dependencies import get_db_session
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import create_database_engine, get_session_factory
from app.models.detection_evidence import DetectionEvidence
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.schemas.contracts import ComponentAvailability, IncidentStatus, SecurityVerdict
from app.services.incident_service import create_incident


@pytest.fixture
def memory_db_engine():
    """Create an isolated in-memory SQLite database engine with StaticPool sharing schema."""
    engine = create_database_engine(
        "sqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def api_client(app_instance: FastAPI, memory_db_engine) -> TestClient:
    """Create a TestClient with overridden get_db_session pointing to in-memory database."""
    session_factory = get_session_factory(memory_db_engine)

    def _override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app_instance.dependency_overrides[get_db_session] = _override_get_db
    with TestClient(app_instance) as client:
        yield client
    app_instance.dependency_overrides.clear()


# ==============================================================================
# 1. Health Endpoint Tests (/api/v1/health)
# ==============================================================================

def test_health_endpoint_success(api_client: TestClient) -> None:
    """Verify GET /api/v1/health returns HTTP 200 with required metadata."""
    response = api_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "sentinel-edr-api"
    assert data["version"] == get_settings().app_version

    # Verify timestamp format ISO 8601 UTC
    ts = data["timestamp"]
    assert ts.endswith("Z")
    parsed_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed_dt.tzinfo is not None

    # Check X-Request-ID propagation
    assert "X-Request-ID" in response.headers


def test_health_endpoint_usable_without_database(api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify GET /api/v1/health remains healthy even when database is completely broken."""
    def _broken_engine():
        raise OperationalError("Unable to open database", None, None)

    monkeypatch.setattr("app.db.session.get_default_engine", _broken_engine)

    response = api_client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


# ==============================================================================
# 2. Status Endpoint Tests (/api/v1/status)
# ==============================================================================

def test_status_endpoint_database_available(api_client: TestClient, monkeypatch: pytest.MonkeyPatch, memory_db_engine) -> None:
    """Verify GET /api/v1/status reports database available and overall degraded for uninitialized modules."""
    monkeypatch.setattr("app.api.routes.status.get_default_engine", lambda: memory_db_engine)

    response = api_client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "degraded"
    components = data["components"]
    assert components["database"] == ComponentAvailability.AVAILABLE.value
    assert components["signature_engine"] == ComponentAvailability.NOT_INITIALIZED.value
    assert components["ml_engine"] == ComponentAvailability.NOT_INITIALIZED.value
    assert components["behavioral_monitor"] == ComponentAvailability.NOT_INITIALIZED.value
    assert components["ai_reporting"] == ComponentAvailability.NOT_INITIALIZED.value

    # Verify timestamp
    assert data["timestamp"].endswith("Z")


def test_status_endpoint_database_unavailable(api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify GET /api/v1/status reports database unavailable when connectivity fails."""
    def _failing_check():
        return ComponentAvailability.UNAVAILABLE

    monkeypatch.setattr("app.api.routes.status._check_database_availability", _failing_check)

    response = api_client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "unavailable"
    assert data["components"]["database"] == ComponentAvailability.UNAVAILABLE.value


def test_status_endpoint_does_not_leak_paths_or_credentials(api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that database errors do not leak filesystem paths or connection strings."""
    class BrokenConn:
        def __enter__(self):
            raise OperationalError("Sensitive DB credentials failed at C:\\secret\\db.sqlite", None, None)
        def __exit__(self, *args):
            pass

    class BrokenEngine:
        def connect(self):
            return BrokenConn()

    monkeypatch.setattr("app.api.routes.status.get_default_engine", lambda: BrokenEngine())

    response = api_client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "unavailable"
    assert data["components"]["database"] == "unavailable"
    response_text = response.text
    assert "secret" not in response_text
    assert "db.sqlite" not in response_text


# ==============================================================================
# 3. Incident Listing Tests (GET /api/v1/incidents)
# ==============================================================================

def test_list_incidents_empty(api_client: TestClient) -> None:
    """Verify GET /api/v1/incidents returns empty list with valid pagination when no records exist."""
    response = api_client.get("/api/v1/incidents")
    assert response.status_code == 200
    data = response.json()

    assert data["items"] == []
    pagination = data["pagination"]
    assert pagination["page"] == 1
    assert pagination["page_size"] == 20
    assert pagination["total_items"] == 0
    assert pagination["total_pages"] == 0


def test_list_incidents_populated_and_paginated(api_client: TestClient, memory_db_engine) -> None:
    """Verify listing populated incidents, pagination boundaries, and sorting."""
    factory = get_session_factory(memory_db_engine)
    with factory() as session:
        for i in range(25):
            create_incident(
                session,
                title=f"Incident {i:02d}",
                incident_type="ransomware",
                verdict="MALICIOUS" if i % 2 == 0 else "SUSPICIOUS",
                risk_score=float(i * 3),
                detected_at=f"2026-10-29T10:{i:02d}:00Z",
            )
        session.commit()

    # Page 1 (default page_size=20)
    res1 = api_client.get("/api/v1/incidents")
    assert res1.status_code == 200
    data1 = res1.json()
    assert len(data1["items"]) == 20
    assert data1["pagination"]["total_items"] == 25
    assert data1["pagination"]["total_pages"] == 2
    assert data1["pagination"]["page"] == 1

    # Verify deterministic ordering: detected_at descending
    assert data1["items"][0]["title"] == "Incident 24"
    assert data1["items"][1]["title"] == "Incident 23"

    # Page 2
    res2 = api_client.get("/api/v1/incidents?page=2&page_size=20")
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2["items"]) == 5
    assert data2["pagination"]["page"] == 2


def test_list_incidents_max_page_size_enforced(api_client: TestClient) -> None:
    """Verify page_size exceeding 100 is rejected with HTTP 422."""
    response = api_client.get("/api/v1/incidents?page_size=101")
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_list_incidents_invalid_pagination_values_rejected(api_client: TestClient) -> None:
    """Verify invalid page (< 1) and invalid page_size (< 1) are rejected with HTTP 422."""
    res_page = api_client.get("/api/v1/incidents?page=0")
    assert res_page.status_code == 422
    assert res_page.json()["error"]["code"] == "VALIDATION_ERROR"

    res_size = api_client.get("/api/v1/incidents?page_size=0")
    assert res_size.status_code == 422
    assert res_size.json()["error"]["code"] == "VALIDATION_ERROR"


def test_list_incidents_filter_by_verdict_and_status(api_client: TestClient, memory_db_engine) -> None:
    """Verify filtering by verdict and status."""
    factory = get_session_factory(memory_db_engine)
    with factory() as session:
        create_incident(
            session,
            title="Malicious Incident",
            incident_type="malware",
            verdict="MALICIOUS",
            risk_score=95.0,
            status="OPEN",
        )
        create_incident(
            session,
            title="Benign Investigation",
            incident_type="malware",
            verdict="BENIGN",
            risk_score=10.0,
            status="RESOLVED",
        )
        session.commit()

    # Filter by verdict MALICIOUS
    res_mal = api_client.get("/api/v1/incidents?verdict=MALICIOUS")
    assert res_mal.status_code == 200
    data_mal = res_mal.json()
    assert data_mal["pagination"]["total_items"] == 1
    assert data_mal["items"][0]["title"] == "Malicious Incident"

    # Filter by status RESOLVED
    res_res = api_client.get("/api/v1/incidents?status=RESOLVED")
    assert res_res.status_code == 200
    data_res = res_res.json()
    assert data_res["pagination"]["total_items"] == 1
    assert data_res["items"][0]["title"] == "Benign Investigation"

    # Filter by invalid verdict
    res_inv_v = api_client.get("/api/v1/incidents?verdict=INVALID_VERDICT")
    assert res_inv_v.status_code == 422
    assert res_inv_v.json()["error"]["code"] == "VALIDATION_ERROR"

    # Filter by invalid status
    res_inv_s = api_client.get("/api/v1/incidents?status=INVALID_STATUS")
    assert res_inv_s.status_code == 422
    assert res_inv_s.json()["error"]["code"] == "VALIDATION_ERROR"


def test_openapi_does_not_advertise_advanced_filters_for_t007(app_instance: FastAPI) -> None:
    """Verify OpenAPI schema does not advertise file_hash, from_time, or to_time for GET /api/v1/incidents."""
    openapi_schema = app_instance.openapi()
    incident_list_op = openapi_schema["paths"]["/api/v1/incidents"]["get"]
    param_names = [p["name"] for p in incident_list_op.get("parameters", [])]
    assert "page" in param_names
    assert "page_size" in param_names
    assert "verdict" in param_names
    assert "status" in param_names
    assert "file_hash" not in param_names
    assert "from_time" not in param_names
    assert "to_time" not in param_names


# ==============================================================================
# 4. Incident Detail Tests (GET /api/v1/incidents/{incident_id})
# ==============================================================================

def test_get_incident_detail_success(api_client: TestClient, memory_db_engine) -> None:
    """Verify GET /api/v1/incidents/{incident_id} returns all detail fields and counts."""
    factory = get_session_factory(memory_db_engine)
    with factory() as session:
        inc = create_incident(
            session,
            title="Target Incident",
            description="Suspicious activity observed.",
            incident_type="process_injection",
            verdict="MALICIOUS",
            risk_score=85.0,
            file_path="C:\\test\\inject.exe",
            file_hash="a" * 64,
            process_id=4567,
        )
        # Add 2 detection evidence records
        ev1 = DetectionEvidence(
            evidence_id=str(uuid4()),
            incident_id=inc.incident_id,
            source="yara",
            indicator="rule_hollowing",
            severity="HIGH",
            description="Process hollowing detected",
            observed_at="2026-10-29T10:00:00Z",
            created_at="2026-10-29T10:00:00Z",
        )
        ev2 = DetectionEvidence(
            evidence_id=str(uuid4()),
            incident_id=inc.incident_id,
            source="ml",
            indicator="pe_score",
            severity="MEDIUM",
            description="High ML risk probability",
            observed_at="2026-10-29T10:01:00Z",
            created_at="2026-10-29T10:01:00Z",
        )
        # Add 1 response action
        act = ResponseAction(
            action_id=str(uuid4()),
            incident_id=inc.incident_id,
            action_type="ALERT",
            status="SUCCEEDED",
            mode="DRY_RUN",
            requested_by="analyst_1",
            requested_at="2026-10-29T10:02:00Z",
        )
        session.add_all([ev1, ev2, act])
        session.commit()
        target_id = inc.incident_id

    response = api_client.get(f"/api/v1/incidents/{target_id}")
    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] == target_id
    assert data["title"] == "Target Incident"
    assert data["description"] == "Suspicious activity observed."
    assert data["incident_type"] == "process_injection"
    assert data["verdict"] == "MALICIOUS"
    assert data["risk_score"] == 85.0
    assert data["status"] == "OPEN"
    assert data["file_path"] == "C:\\test\\inject.exe"
    assert data["file_hash"] == "a" * 64
    assert data["process_id"] == 4567
    assert data["evidence_count"] == 2
    assert data["response_action_count"] == 1


def test_get_incident_detail_not_found(api_client: TestClient) -> None:
    """Verify unknown incident UUID returns HTTP 404 with RESOURCE_NOT_FOUND code."""
    missing_id = str(uuid4())
    response = api_client.get(f"/api/v1/incidents/{missing_id}")
    assert response.status_code == 404
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert missing_id in data["error"]["message"]
    assert "request_id" in data["error"]


def test_get_incident_detail_invalid_uuid(api_client: TestClient) -> None:
    """Verify invalid UUID parameter returns HTTP 422 with VALIDATION_ERROR code."""
    response = api_client.get("/api/v1/incidents/not-a-valid-uuid")
    assert response.status_code == 422
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "request_id" in data["error"]


# ==============================================================================
# 5. Error Envelope and Diagnostic Tests
# ==============================================================================

def test_unhandled_server_error_envelope(app_instance: FastAPI) -> None:
    """Verify unhandled exceptions return HTTP 500 without leaking stack traces or internal secrets."""
    app_instance.debug = False

    # Add a route that raises an unhandled exception with sensitive data
    @app_instance.get("/api/v1/test-crash")
    def _crash_route():
        raise RuntimeError("CRITICAL_PASSWORD_SECRET_12345 in /etc/passwd")

    client = TestClient(app_instance, raise_server_exceptions=False)
    response = client.get("/api/v1/test-crash")
    assert response.status_code == 500
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
    assert data["error"]["message"] == "An unexpected internal server error occurred."
    assert "CRITICAL_PASSWORD_SECRET" not in response.text
    assert "/etc/passwd" not in response.text
    assert "request_id" in data["error"]
