"""YARA signature scanning service for Sentinel-EDR.

Provides compiled signature-rule loading, safe bounded rule discovery, deterministic
scanning, and structured match reporting.
"""

from dataclasses import dataclass, field
from enum import Enum
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Union

import yara

from app.core.config import get_settings
from app.schemas.contracts import ComponentAvailability

logger = logging.getLogger("sentinel.services.yara_scanner")

SUPPORTED_RULE_EXTENSIONS = {".yar", ".yara"}
MAX_STRING_MATCH_INSTANCES_PER_RULE = 50


# ==============================================================================
# Exceptions
# ==============================================================================

class YaraScannerError(Exception):
    """Base exception for all YARA scanner operations."""


class YaraScannerNotReadyError(YaraScannerError):
    """Raised when scan is attempted before rules are compiled and ready."""


class YaraRuleCompilationError(YaraScannerError):
    """Raised when compilation of rule files fails due to syntax or validation errors."""


class YaraScanTimeoutError(YaraScannerError):
    """Raised when a scan exceeds the configured execution timeout."""


class YaraFileAccessError(YaraScannerError):
    """Raised when the target file cannot be accessed or read."""


class YaraFileTooLargeError(YaraScannerError):
    """Raised when the target file exceeds the configured maximum scan file size."""


# ==============================================================================
# Enums and Structured Match Models
# ==============================================================================

class YaraScanStatus(str, Enum):
    """Status outcome of a YARA file scan execution."""
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class YaraScannerState(str, Enum):
    """Lifecycle and operational readiness state of the YARA scanner."""
    NOT_INITIALIZED = "not_initialized"
    NO_RULES_AVAILABLE = "no_rules_available"
    READY = "ready"
    COMPILATION_FAILED = "compilation_failed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class YaraStringMatch:
    """Safe bounded summary of an individual matched string instance."""
    identifier: str
    offset: int
    length: int


@dataclass(frozen=True)
class YaraRuleMatch:
    """Structured details of a single matched YARA rule."""
    rule_name: str
    namespace: str
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    matched_strings: List[YaraStringMatch] = field(default_factory=list)


@dataclass(frozen=True)
class YaraScanResult:
    """Deterministic result of a YARA file scan operation.

    A completed scan with is_matched=False indicates only that the configured
    rules did not trigger. It does NOT automatically assert a BENIGN security verdict.
    """
    file_path: str
    status: YaraScanStatus
    is_matched: bool
    matched_rules: List[YaraRuleMatch] = field(default_factory=list)
    matched_rule_names: List[str] = field(default_factory=list)
    match_count: int = 0
    scan_duration_ms: float = 0.0
    error_message: Optional[str] = None
    timed_out: bool = False


# ==============================================================================
# YaraScanner Service
# ==============================================================================

class YaraScanner:
    """Thread-safe YARA signature scanner service."""

    def __init__(
        self,
        rules_dir: Optional[Union[str, Path]] = None,
        *,
        default_timeout: Optional[int] = None,
        max_file_size: Optional[int] = None,
    ) -> None:
        """Initialize the YARA scanner without compiling rules at instantiation.

        Args:
            rules_dir: Optional custom path to directory containing .yar / .yara files.
            default_timeout: Scan timeout in seconds (must be > 0).
            max_file_size: Maximum allowable target file size in bytes.
        """
        settings = get_settings()
        self._rules_dir = Path(rules_dir or settings.yara_rules_dir)
        self._default_timeout = default_timeout or settings.yara_scan_timeout_seconds
        self._max_file_size = max_file_size or settings.yara_max_file_size_bytes

        if self._default_timeout <= 0:
            raise ValueError(
                f"default_timeout must be a positive integer, got: {self._default_timeout}"
            )
        if self._max_file_size <= 0:
            raise ValueError(
                f"max_file_size must be a positive integer, got: {self._max_file_size}"
            )

        self._compiled_rules: Optional[yara.Rules] = None
        self._state: YaraScannerState = YaraScannerState.NOT_INITIALIZED
        self._rules_count: int = 0
        self._loaded_namespaces: List[str] = []
        self._last_error: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def state(self) -> YaraScannerState:
        """Return the current operational lifecycle state of the scanner."""
        return self._state

    @property
    def is_ready(self) -> bool:
        """Check if rules have been compiled and the scanner is ready to process files."""
        return self._state == YaraScannerState.READY and self._compiled_rules is not None

    @property
    def rules_count(self) -> int:
        """Return the number of compiled rule files currently loaded."""
        return self._rules_count

    @property
    def loaded_namespaces(self) -> List[str]:
        """Return sorted list of rule namespaces currently active."""
        return list(self._loaded_namespaces)

    @property
    def last_error(self) -> Optional[str]:
        """Return description of the most recent compilation or operational failure."""
        return self._last_error

    @property
    def rules_dir(self) -> Path:
        """Return configured rules directory path."""
        return self._rules_dir

    def get_availability(self) -> ComponentAvailability:
        """Map internal scanner state to standardized ComponentAvailability."""
        if self._state == YaraScannerState.READY:
            return ComponentAvailability.AVAILABLE
        if self._state in (YaraScannerState.NOT_INITIALIZED, YaraScannerState.NO_RULES_AVAILABLE):
            return ComponentAvailability.NOT_INITIALIZED
        if self._state == YaraScannerState.COMPILATION_FAILED:
            return ComponentAvailability.UNAVAILABLE
        if self._state == YaraScannerState.UNAVAILABLE:
            return ComponentAvailability.UNAVAILABLE
        return ComponentAvailability.UNKNOWN

    def discover_rule_files(
        self,
        directory: Optional[Union[str, Path]] = None,
    ) -> Dict[str, str]:
        """Discover valid YARA rule files within the target directory.

        Accepts only regular files ending in .yar or .yara. Does not follow
        symlinks outside the target directory. Produces deterministic namespaces.

        Args:
            directory: Directory to inspect (defaults to self._rules_dir).

        Returns:
            Dictionary mapping deterministic namespace names to absolute file paths.
        """
        target_dir = Path(directory or self._rules_dir).resolve()

        if not target_dir.exists() or not target_dir.is_dir():
            logger.debug("Rule directory '%s' does not exist or is not a directory", target_dir)
            return {}

        discovered: Dict[str, str] = {}
        # Deterministically iterate sorted entries
        try:
            entries = sorted(target_dir.iterdir(), key=lambda p: p.name.lower())
        except OSError as exc:
            logger.warning("Failed to list rule directory '%s': %s", target_dir, exc)
            return {}

        for entry in entries:
            # Skip hidden files and non-rule extensions
            if entry.name.startswith(".") or entry.suffix.lower() not in SUPPORTED_RULE_EXTENSIONS:
                continue

            # Must be a regular file; avoid symlinks pointing outside target_dir
            try:
                resolved_entry = entry.resolve()
                if not entry.is_file() or not resolved_entry.is_file():
                    continue
                # Ensure the resolved file resides within target_dir
                resolved_entry.relative_to(target_dir)
            except (OSError, ValueError):
                continue

            # Stable namespace derived from file stem
            namespace = entry.stem.lower().replace("-", "_").replace(".", "_")
            if not namespace:
                namespace = "default"

            # Avoid collision by appending deterministic suffix if needed
            unique_ns = namespace
            counter = 1
            while unique_ns in discovered:
                unique_ns = f"{namespace}_{counter}"
                counter += 1

            discovered[unique_ns] = str(resolved_entry)

        return discovered

    def load_rules(
        self,
        rules_dir: Optional[Union[str, Path]] = None,
    ) -> int:
        """Discover and compile YARA rules from the configured directory.

        Thread-safe. Replaces the active rule set only upon successful compilation.
        If compilation fails, preserves any previously compiled rules.

        Args:
            rules_dir: Optional directory override.

        Returns:
            Number of rule files compiled.

        Raises:
            YaraRuleCompilationError: If syntax or compilation errors occur.
        """
        with self._lock:
            effective_dir = Path(rules_dir or self._rules_dir)
            rule_files = self.discover_rule_files(effective_dir)

            if not rule_files:
                logger.warning("No YARA rule files found in '%s'", effective_dir)
                if self._compiled_rules is None:
                    self._state = YaraScannerState.NO_RULES_AVAILABLE
                    self._rules_count = 0
                    self._loaded_namespaces = []
                return 0

            try:
                compiled = yara.compile(filepaths=rule_files)
            except yara.SyntaxError as exc:
                err_msg = f"YARA syntax error: {exc}"
                self._last_error = err_msg
                logger.error("Failed to compile YARA rules in '%s': %s", effective_dir, exc)
                if self._compiled_rules is None:
                    self._state = YaraScannerState.COMPILATION_FAILED
                raise YaraRuleCompilationError(err_msg) from exc
            except yara.Error as exc:
                err_msg = f"YARA compilation error: {exc}"
                self._last_error = err_msg
                logger.error("Failed to compile YARA rules in '%s': %s", effective_dir, exc)
                if self._compiled_rules is None:
                    self._state = YaraScannerState.COMPILATION_FAILED
                raise YaraRuleCompilationError(err_msg) from exc

            # Compilation succeeded: update active scanner state
            self._compiled_rules = compiled
            self._rules_count = len(rule_files)
            self._loaded_namespaces = sorted(rule_files.keys())
            self._state = YaraScannerState.READY
            self._last_error = None
            logger.info("Successfully compiled %d YARA rule file(s)", self._rules_count)
            return self._rules_count

    def reload_rules(
        self,
        rules_dir: Optional[Union[str, Path]] = None,
    ) -> int:
        """Reload and recompile rules from the configured directory.

        Preserves the previous valid rule set if the reload fails.

        Returns:
            Number of rule files compiled.

        Raises:
            YaraRuleCompilationError: If compilation of the new set fails.
        """
        return self.load_rules(rules_dir=rules_dir)

    def scan_file(
        self,
        file_path: Union[str, Path],
        *,
        timeout_seconds: Optional[int] = None,
    ) -> YaraScanResult:
        """Scan a file on disk against the compiled YARA rule set.

        Args:
            file_path: Path to the target file.
            timeout_seconds: Optional explicit scan timeout in seconds.

        Returns:
            Structured YaraScanResult identifying matches and scan status.

        Raises:
            YaraScannerNotReadyError: If rules have not been compiled and scanner is not ready.
            FileNotFoundError: If the target file does not exist.
            IsADirectoryError: If the target path is a directory.
            ValueError: If path is not a regular file or timeout is non-positive.
            PermissionError: If target file cannot be read.
            YaraFileTooLargeError: If target file exceeds maximum allowable size.
            YaraScannerError: On unhandled internal scanning errors.
        """
        if not self.is_ready or self._compiled_rules is None:
            raise YaraScannerNotReadyError(
                f"YARA scanner is not ready (state={self._state.value}). Rules must be loaded before scanning."
            )

        timeout = timeout_seconds if timeout_seconds is not None else self._default_timeout
        if timeout <= 0:
            raise ValueError(f"timeout_seconds must be a positive integer, got: {timeout}")

        path_obj = Path(file_path).resolve()

        if not path_obj.exists():
            raise FileNotFoundError(f"Target file does not exist: {file_path}")

        if path_obj.is_dir():
            raise IsADirectoryError(f"Target path is a directory, not a regular file: {file_path}")

        if not path_obj.is_file():
            raise ValueError(f"Target path is not a regular file: {file_path}")

        try:
            file_size = path_obj.stat().st_size
        except OSError as exc:
            raise PermissionError(f"Cannot access target file '{file_path}': {exc}") from exc

        if file_size > self._max_file_size:
            raise YaraFileTooLargeError(
                f"File size ({file_size} bytes) exceeds maximum configured limit ({self._max_file_size} bytes)"
            )

        start_time = time.perf_counter()
        try:
            raw_matches = self._compiled_rules.match(
                filepath=str(path_obj),
                timeout=timeout,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000.0
        except yara.TimeoutError:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("YARA scan timed out on '%s' after %d seconds", path_obj, timeout)
            return YaraScanResult(
                file_path=str(path_obj),
                status=YaraScanStatus.TIMED_OUT,
                is_matched=False,
                matched_rules=[],
                matched_rule_names=[],
                match_count=0,
                scan_duration_ms=round(duration_ms, 2),
                error_message=f"Scan timed out after {timeout} seconds",
                timed_out=True,
            )
        except yara.Error as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("YARA scan failed on '%s': %s", path_obj, exc)
            return YaraScanResult(
                file_path=str(path_obj),
                status=YaraScanStatus.FAILED,
                is_matched=False,
                matched_rules=[],
                matched_rule_names=[],
                match_count=0,
                scan_duration_ms=round(duration_ms, 2),
                error_message=str(exc),
                timed_out=False,
            )

        # Parse matches into safe bounded structures
        rule_matches: List[YaraRuleMatch] = []
        for m in raw_matches:
            safe_strings: List[YaraStringMatch] = []
            for sm in getattr(m, "strings", []):
                for inst in getattr(sm, "instances", []):
                    safe_strings.append(
                        YaraStringMatch(
                            identifier=str(getattr(sm, "identifier", "$unknown")),
                            offset=int(getattr(inst, "offset", 0)),
                            length=len(getattr(inst, "matched_data", b"")),
                        )
                    )
                    if len(safe_strings) >= MAX_STRING_MATCH_INSTANCES_PER_RULE:
                        break
                if len(safe_strings) >= MAX_STRING_MATCH_INSTANCES_PER_RULE:
                    break

            rule_matches.append(
                YaraRuleMatch(
                    rule_name=str(m.rule),
                    namespace=str(m.namespace),
                    tags=list(m.tags),
                    metadata=dict(m.meta),
                    matched_strings=safe_strings,
                )
            )

        return YaraScanResult(
            file_path=str(path_obj),
            status=YaraScanStatus.COMPLETED,
            is_matched=len(rule_matches) > 0,
            matched_rules=rule_matches,
            matched_rule_names=[r.rule_name for r in rule_matches],
            match_count=len(rule_matches),
            scan_duration_ms=round(duration_ms, 2),
            error_message=None,
            timed_out=False,
        )


# Global default instance (not initialized at import time)
_default_scanner: Optional[YaraScanner] = None
_scanner_init_lock = threading.Lock()


def get_default_yara_scanner() -> YaraScanner:
    """Return the global default YaraScanner instance.

    Note: The returned instance is not automatically initialized or loaded.
    Callers must invoke scanner.load_rules() before scanning.
    """
    global _default_scanner
    if _default_scanner is None:
        with _scanner_init_lock:
            if _default_scanner is None:
                _default_scanner = YaraScanner()
    return _default_scanner


def reset_default_yara_scanner() -> None:
    """Reset the global default YaraScanner singleton (for test isolation)."""
    global _default_scanner
    with _scanner_init_lock:
        _default_scanner = None
