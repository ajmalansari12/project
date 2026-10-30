"""Pytest configuration and shared fixtures for backend tests."""

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure backend-api directory is on sys.path for direct module imports
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent / "backend-api"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import Settings
from app.main import create_application


@pytest.fixture
def test_settings() -> Settings:
    """Fixture providing isolated test configuration."""
    return Settings(
        app_name="Sentinel-EDR-Test",
        app_version="0.1.0-test",
        environment="testing",
        debug=True,
        api_host="127.0.0.1",
        api_port=8080,
        log_level="DEBUG",
    )


@pytest.fixture
def app_instance(test_settings: Settings) -> FastAPI:
    """Fixture providing a fresh FastAPI application with test settings."""
    return create_application(settings=test_settings)


@pytest.fixture
def test_client(app_instance: FastAPI) -> TestClient:
    """Fixture providing a synchronous TestClient for HTTP requests."""
    return TestClient(app_instance)
