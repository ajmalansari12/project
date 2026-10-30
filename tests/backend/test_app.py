"""Automated tests for FastAPI application scaffold, configuration, and logging."""

import logging
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from app.core.config import Settings
from app.core.logging_config import setup_logging
from app.main import app, create_application


def test_app_import_and_instance() -> None:
    """Verify that the FastAPI application can be imported and is a valid FastAPI instance."""
    assert app is not None
    assert isinstance(app, FastAPI)
    assert app.title == "Sentinel-EDR"


def test_openapi_generation(app_instance: FastAPI) -> None:
    """Verify that OpenAPI schema can be successfully generated without errors."""
    openapi_schema = app_instance.openapi()
    assert openapi_schema is not None
    assert isinstance(openapi_schema, dict)
    assert "openapi" in openapi_schema
    assert openapi_schema["info"]["title"] == "Sentinel-EDR-Test"
    assert openapi_schema["info"]["version"] == "0.1.0-test"


def test_config_defaults() -> None:
    """Verify default configuration values."""
    settings = Settings()
    assert settings.app_name == "Sentinel-EDR"
    assert settings.app_version == "0.1.0"
    assert settings.environment == "development"
    assert settings.api_host == "127.0.0.1"
    assert settings.api_port == 8000
    assert settings.log_level == "INFO"
    assert settings.debug is False
    assert settings.database_url == "sqlite:///.data/sentinel_edr.db"
    assert settings.analysis_recover_interrupted_on_startup is False


def test_config_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that valid environment variables override defaults."""
    monkeypatch.setenv("APP_NAME", "Sentinel-Custom")
    monkeypatch.setenv("APP_VERSION", "1.2.3")
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("API_PORT", "9000")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///custom.db")
    monkeypatch.setenv("ANALYSIS_RECOVER_INTERRUPTED_ON_STARTUP", "true")

    overridden = Settings()
    assert overridden.app_name == "Sentinel-Custom"
    assert overridden.app_version == "1.2.3"
    assert overridden.environment == "staging"
    assert overridden.api_port == 9000
    assert overridden.log_level == "DEBUG"
    assert overridden.debug is True
    assert overridden.database_url == "sqlite:///custom.db"
    assert overridden.analysis_recover_interrupted_on_startup is True


def test_invalid_config_port_low() -> None:
    """Verify that a port below 1 raises a ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(api_port=0)
    assert "Port must be between 1 and 65535" in str(exc_info.value)


def test_invalid_config_port_high() -> None:
    """Verify that a port above 65535 raises a ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(api_port=70000)
    assert "Port must be between 1 and 65535" in str(exc_info.value)


def test_invalid_config_log_level() -> None:
    """Verify that an unrecognized log level raises a ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(log_level="TRACE")
    assert "Invalid log level" in str(exc_info.value)


def test_invalid_config_empty_app_name() -> None:
    """Verify that an empty string for app_name raises a ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(app_name="   ")
    assert "Value must not be empty or whitespace" in str(exc_info.value)


def test_logging_no_duplicate_handlers() -> None:
    """Verify that repeated setup_logging calls do not register duplicate stream handlers."""
    test_logger_name = "test_duplicate_check_logger"
    logger = logging.getLogger(test_logger_name)
    logger.handlers.clear()

    setup_logging(log_level="DEBUG", logger_name=test_logger_name)
    initial_count = len([h for h in logger.handlers if isinstance(h, logging.StreamHandler) and h.stream == sys.stdout])

    # Second call should not append duplicate stdout handler
    setup_logging(log_level="DEBUG", logger_name=test_logger_name)
    second_count = len([h for h in logger.handlers if isinstance(h, logging.StreamHandler) and h.stream == sys.stdout])

    assert initial_count == 1
    assert second_count == 1


def test_logging_level_configuration() -> None:
    """Verify that log level is correctly applied to the logger."""
    test_logger_name = "test_level_logger"
    logger = setup_logging(log_level="WARNING", logger_name=test_logger_name)
    assert logger.level == logging.WARNING


def test_no_external_dependency_at_startup(app_instance: FastAPI) -> None:
    """Verify the application creates cleanly without network access or database connections."""
    assert app_instance is not None
    assert app_instance.router is not None


def test_lifespan_yara_disabled_does_not_compile_rules() -> None:
    """Verify that when YARA is disabled, lifespan does not compile rules and scanner remains unready."""
    from fastapi.testclient import TestClient
    from app.services.yara_scanner import YaraScannerState, get_default_yara_scanner, reset_default_yara_scanner

    reset_default_yara_scanner()
    settings = Settings(
        yara_enabled=False,
        yara_rules_dir="tests/fixtures/yara",
        analysis_workers_enabled=False,
    )
    test_app = create_application(settings=settings)

    with TestClient(test_app):
        scanner = get_default_yara_scanner()
        assert scanner.is_ready is False
        assert scanner.rules_count == 0
        assert scanner.state == YaraScannerState.NOT_INITIALIZED

    reset_default_yara_scanner()


def test_lifespan_yara_enabled_with_valid_rules_compiles_and_readies_scanner() -> None:
    """Verify that when YARA is enabled with valid rules, lifespan compiles them and scanner becomes ready."""
    from fastapi.testclient import TestClient
    from app.services.yara_scanner import YaraScannerState, get_default_yara_scanner, reset_default_yara_scanner

    reset_default_yara_scanner()
    settings = Settings(
        yara_enabled=True,
        yara_rules_dir="tests/fixtures/yara",
        analysis_workers_enabled=False,
    )
    test_app = create_application(settings=settings)

    with TestClient(test_app):
        scanner = get_default_yara_scanner()
        assert scanner.is_ready is True
        assert scanner.rules_count == 2
        assert scanner.state == YaraScannerState.READY
        assert "synthetic_threat" in scanner.loaded_namespaces
        assert "harmless_marker" in scanner.loaded_namespaces

    reset_default_yara_scanner()


def test_lifespan_yara_enabled_with_missing_rules_does_not_crash_startup(tmp_path: Path) -> None:
    """Verify that missing rules directory does not crash application startup and leaves scanner unready."""
    from fastapi.testclient import TestClient
    from app.services.yara_scanner import YaraScannerState, get_default_yara_scanner, reset_default_yara_scanner

    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()

    reset_default_yara_scanner()
    settings = Settings(
        yara_enabled=True,
        yara_rules_dir=str(empty_dir),
        analysis_workers_enabled=False,
    )
    test_app = create_application(settings=settings)

    with TestClient(test_app):
        scanner = get_default_yara_scanner()
        assert scanner.is_ready is False
        assert scanner.rules_count == 0
        assert scanner.state == YaraScannerState.NO_RULES_AVAILABLE

    reset_default_yara_scanner()


def test_lifespan_yara_enabled_with_compilation_failure_does_not_crash_startup(tmp_path: Path) -> None:
    """Verify that YARA syntax/compilation error does not crash application startup and updates state."""
    from fastapi.testclient import TestClient
    from app.services.yara_scanner import YaraScannerState, get_default_yara_scanner, reset_default_yara_scanner

    bad_rule = tmp_path / "syntax_error.yar"
    bad_rule.write_text("rule BrokenRule { strings: $a = \"ok\" condition: invalid syntax here }")

    reset_default_yara_scanner()
    settings = Settings(
        yara_enabled=True,
        yara_rules_dir=str(tmp_path),
        analysis_workers_enabled=False,
    )
    test_app = create_application(settings=settings)

    with TestClient(test_app):
        scanner = get_default_yara_scanner()
        assert scanner.is_ready is False
        assert scanner.rules_count == 0
        assert scanner.state == YaraScannerState.COMPILATION_FAILED
        assert scanner.last_error is not None

    reset_default_yara_scanner()
