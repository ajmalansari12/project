"""Application configuration management for Sentinel-EDR.

Loads validated settings from environment variables or a local .env file.
"""

from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class Settings(BaseSettings):
    """Validated application settings model."""

    app_name: str = Field(
        default="Sentinel-EDR",
        description="Public name of the application.",
    )
    app_version: str = Field(
        default="0.1.0",
        description="Semantic version string for the backend service.",
    )
    environment: str = Field(
        default="development",
        description="Deployment environment name (e.g. development, testing, production).",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode and verbose diagnostic output.",
    )
    api_host: str = Field(
        default="127.0.0.1",
        description="Host interface the backend server binds to.",
    )
    api_port: int = Field(
        default=8000,
        description="Network port the backend server listens on.",
    )
    log_level: str = Field(
        default="INFO",
        description="Minimum log severity level for standard loggers.",
    )
    database_url: str = Field(
        default="sqlite:///.data/sentinel_edr.db",
        description="Database connection URL for SQLAlchemy.",
    )
    yara_rules_dir: str = Field(
        default="rules/yara",
        description="Path to local directory containing YARA rule files (.yar, .yara).",
    )
    yara_enabled: bool = Field(
        default=False,
        description="Whether the YARA signature scanning stage is enabled in the analysis pipeline.",
    )
    yara_scan_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Default scan timeout in seconds for YARA rule evaluation.",
    )
    yara_max_file_size_bytes: int = Field(
        default=104857600,
        ge=1,
        description="Maximum allowable file size in bytes for YARA scanning (default 100MB).",
    )
    analysis_queue_capacity: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Maximum capacity of the in-memory analysis dispatch queue.",
    )
    analysis_worker_count: int = Field(
        default=2,
        ge=1,
        le=32,
        description="Number of concurrent worker threads processing analysis jobs.",
    )
    analysis_workers_enabled: bool = Field(
        default=False,
        description="Whether background analysis workers are automatically started on application lifespan.",
    )
    analysis_worker_poll_interval_seconds: float = Field(
        default=0.5,
        ge=0.05,
        le=30.0,
        description="Polling interval in seconds for queue workers and recovery checks.",
    )
    analysis_recover_interrupted_on_startup: bool = Field(
        default=False,
        description="Whether to transition interrupted IN_PROGRESS analysis jobs to FAILED during startup recovery.",
    )
    pe_max_file_size_bytes: int = Field(
        default=104857600,
        ge=1,
        description="Maximum allowable file size in bytes for PE feature extraction (default 100MB).",
    )
    ember_dataset_dir: str = Field(
        default=".data/ember",
        description="Local directory path for EMBER dataset archives, JSONL shards, and vectorized data.",
    )
    ml_models_dir: str = Field(
        default=".data/models",
        description="Local directory path for trained ML model artifacts and metadata.",
    )
    ml_enabled: bool = Field(
        default=False,
        description="Whether the static PE ML classification stage is enabled in the analysis pipeline.",
    )
    ml_model_path: str = Field(
        default=".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx",
        description="Path to production ONNX model artifact.",
    )
    ml_metadata_path: str = Field(
        default=".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2_onnx_metadata.json",
        description="Path to production ONNX model metadata JSON.",
    )
    ml_operating_threshold: Optional[float] = Field(
        default=0.8856,
        description="Operating threshold for ML classification.",
    )
    ml_verify_hash: bool = Field(
        default=True,
        description="Whether to verify model artifact SHA-256 on load.",
    )
    sensor_enabled: bool = Field(
        default=False,
        description="Whether the endpoint filesystem sensor is enabled.",
    )
    sensor_monitored_directories: str = Field(
        default="",
        description="Comma-separated list of local directory paths monitored by the filesystem sensor.",
    )
    sensor_poll_interval_seconds: float = Field(
        default=0.5,
        ge=0.05,
        le=30.0,
        description="Polling interval in seconds for directory monitoring sweeps.",
    )
    sensor_debounce_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=60.0,
        description="Sliding debounce window in seconds to coalesce rapid duplicate file events.",
    )
    sensor_auto_submit_for_analysis: bool = Field(
        default=True,
        description="Whether to automatically submit eligible observed files to the analysis queue.",
    )
    sensor_eligible_extensions: str = Field(
        default=".exe,.dll,.sys,.scr,.com,.pif,.bin",
        description="Comma-separated list of file extensions eligible for automatic analysis queue submission.",
    )
    sensor_follow_symlinks: bool = Field(
        default=False,
        description="Whether the filesystem sensor follows directory symlinks and junctions.",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator(
        "app_name",
        "app_version",
        "environment",
        "database_url",
        "yara_rules_dir",
        "ember_dataset_dir",
        "ml_models_dir",
        "ml_model_path",
        "ml_metadata_path",
        mode="before",
    )
    @classmethod
    def validate_non_empty_string(cls, v: str) -> str:
        """Ensure string fields are not empty or solely whitespace."""
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                raise ValueError("Value must not be empty or whitespace.")
            return stripped
        return v

    @field_validator("api_port", mode="before")
    @classmethod
    def validate_port_range(cls, v: int) -> int:
        """Validate network port is within the legal 1-65535 range."""
        try:
            port = int(v)
        except (ValueError, TypeError) as err:
            raise ValueError("Port must be a valid integer.") from err
        if not (1 <= port <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {port}.")
        return port

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Normalize and validate log level strings."""
        if not isinstance(v, str):
            raise ValueError("Log level must be a string.")
        normalized = v.strip().upper()
        if normalized not in VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid log level '{v}'. Must be one of: {sorted(VALID_LOG_LEVELS)}."
            )
        return normalized


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
