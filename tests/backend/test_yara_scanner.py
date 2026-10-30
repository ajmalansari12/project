"""Automated unit and integration tests for YARA signature scanner service."""

import hashlib
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
import yara

from app.schemas.contracts import ComponentAvailability
from app.services.yara_scanner import (
    YaraFileAccessError,
    YaraFileTooLargeError,
    YaraRuleCompilationError,
    YaraRuleMatch,
    YaraScanner,
    YaraScannerError,
    YaraScannerNotReadyError,
    YaraScannerState,
    YaraScanResult,
    YaraScanStatus,
    YaraScanTimeoutError,
    get_default_yara_scanner,
)

FIXTURES_YARA_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "yara"


# ==============================================================================
# 1. Scanner Lifecycle, State, and Component Availability Tests
# ==============================================================================

def test_rule_loading_not_performed_at_import_time():
    """Verify that importing module and instantiating YaraScanner does not compile rules."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    assert scanner.state == YaraScannerState.NOT_INITIALIZED
    assert scanner.is_ready is False
    assert scanner.rules_count == 0
    assert scanner.loaded_namespaces == []
    assert scanner.last_error is None


def test_package_installed_does_not_imply_ready():
    """Verify that yara library availability alone reports NOT_INITIALIZED, not AVAILABLE."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    assert scanner.get_availability() == ComponentAvailability.NOT_INITIALIZED


def test_missing_or_empty_rule_directory_reported_accurately():
    """Verify missing directory and empty directory result in NO_RULES_AVAILABLE state."""
    # Missing directory
    missing_dir = Path(tempfile.gettempdir()) / f"missing_yara_{uuid4().hex}"
    scanner = YaraScanner(rules_dir=missing_dir)
    loaded = scanner.load_rules()
    assert loaded == 0
    assert scanner.state == YaraScannerState.NO_RULES_AVAILABLE
    assert scanner.is_ready is False
    assert scanner.get_availability() == ComponentAvailability.NOT_INITIALIZED

    # Empty directory
    with tempfile.TemporaryDirectory() as empty_dir:
        scanner2 = YaraScanner(rules_dir=empty_dir)
        loaded2 = scanner2.load_rules()
        assert loaded2 == 0
        assert scanner2.state == YaraScannerState.NO_RULES_AVAILABLE
        assert scanner2.is_ready is False


def test_load_valid_fixture_rules_makes_scanner_ready():
    """Verify loading valid fixture rules transitions scanner to READY and AVAILABLE."""
    assert FIXTURES_YARA_DIR.exists()
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    loaded_count = scanner.load_rules()
    assert loaded_count >= 2
    assert scanner.state == YaraScannerState.READY
    assert scanner.is_ready is True
    assert scanner.rules_count == loaded_count
    assert len(scanner.loaded_namespaces) == loaded_count
    assert scanner.get_availability() == ComponentAvailability.AVAILABLE


def test_unsupported_extensions_and_non_rule_files_ignored():
    """Verify scanner only discovers .yar and .yara files and ignores unrelated files."""
    with tempfile.TemporaryDirectory() as td:
        dir_path = Path(td)
        # Valid rule
        (dir_path / "valid.yar").write_text("rule Valid1 { condition: true }", encoding="utf-8")
        # Non-rule extensions
        (dir_path / "notes.txt").write_text("not a rule", encoding="utf-8")
        (dir_path / "config.json").write_text("{}", encoding="utf-8")
        (dir_path / "backup.yar.bak").write_text("rule Bak { condition: true }", encoding="utf-8")

        scanner = YaraScanner(rules_dir=dir_path)
        discovered = scanner.discover_rule_files()
        assert len(discovered) == 1
        assert "valid" in discovered

        loaded = scanner.load_rules()
        assert loaded == 1
        assert scanner.is_ready is True


def test_rule_discovery_is_deterministic():
    """Verify rule discovery produces identical ordering and stable namespaces."""
    with tempfile.TemporaryDirectory() as td:
        dir_path = Path(td)
        (dir_path / "c_rule.yar").write_text("rule C { condition: true }", encoding="utf-8")
        (dir_path / "a_rule.yara").write_text("rule A { condition: true }", encoding="utf-8")
        (dir_path / "b_rule.yar").write_text("rule B { condition: true }", encoding="utf-8")

        scanner = YaraScanner(rules_dir=dir_path)
        discovered1 = scanner.discover_rule_files()
        discovered2 = scanner.discover_rule_files()

        assert list(discovered1.keys()) == list(discovered2.keys())
        assert list(discovered1.keys()) == ["a_rule", "b_rule", "c_rule"]


def test_invalid_rule_syntax_raises_clear_error_and_updates_state():
    """Verify broken YARA syntax raises YaraRuleCompilationError and sets COMPILATION_FAILED."""
    with tempfile.TemporaryDirectory() as td:
        dir_path = Path(td)
        (dir_path / "broken.yar").write_text("rule BrokenRule { invalid syntax here }", encoding="utf-8")

        scanner = YaraScanner(rules_dir=dir_path)
        with pytest.raises(YaraRuleCompilationError, match="syntax error"):
            scanner.load_rules()

        assert scanner.state == YaraScannerState.COMPILATION_FAILED
        assert scanner.is_ready is False
        assert scanner.get_availability() == ComponentAvailability.UNAVAILABLE
        assert "syntax error" in scanner.last_error.lower()


def test_failed_reload_preserves_previously_compiled_rules():
    """Verify that a failed reload preserves the last successfully loaded compiled rules."""
    with tempfile.TemporaryDirectory() as td:
        dir_path = Path(td)
        rule_file = dir_path / "initial.yar"
        rule_file.write_text("rule Initial { condition: true }", encoding="utf-8")

        scanner = YaraScanner(rules_dir=dir_path)
        loaded = scanner.load_rules()
        assert loaded == 1
        assert scanner.is_ready is True
        assert scanner.rules_count == 1

        # Now corrupt the rule file
        rule_file.write_text("rule Corrupted { !!! syntax error !!! }", encoding="utf-8")

        with pytest.raises(YaraRuleCompilationError):
            scanner.reload_rules()

        # Scanner must still be ready with the initial compiled rules preserved
        assert scanner.is_ready is True
        assert scanner.rules_count == 1
        assert scanner.last_error is not None

        # Verify scanning still works using preserved rules
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("any content")
            tf_path = Path(tf.name)
        try:
            res = scanner.scan_file(tf_path)
            assert res.status == YaraScanStatus.COMPLETED
            assert res.is_matched is True
            assert res.matched_rule_names == ["Initial"]
        finally:
            if tf_path.exists():
                tf_path.unlink()


# ==============================================================================
# 2. Scanning and Structured Match Results Tests
# ==============================================================================

def test_scan_single_matching_fixture_file():
    """Verify synthetic test file matches expected rule and returns structured metadata."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write("prefix_data ... SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_ALPHA ... suffix_data")
        tf_path = Path(tf.name)

    try:
        result = scanner.scan_file(tf_path)
        assert isinstance(result, YaraScanResult)
        assert result.status == YaraScanStatus.COMPLETED
        assert result.is_matched is True
        assert result.match_count == 1
        assert "SyntheticThreatAlpha" in result.matched_rule_names
        assert result.timed_out is False
        assert result.error_message is None
        assert result.scan_duration_ms >= 0.0

        match = result.matched_rules[0]
        assert isinstance(match, YaraRuleMatch)
        assert match.rule_name == "SyntheticThreatAlpha"
        assert "test_indicator" in match.tags
        assert "signature" in match.tags
        assert match.metadata.get("severity") == "HIGH"
        assert match.metadata.get("synthetic_id") == "SYN-001"
        assert len(match.matched_strings) > 0
        assert match.matched_strings[0].identifier == "$token"
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_scan_multiple_matching_rules():
    """Verify a file triggering multiple rules reports all matched rule objects correctly."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(
            "header: SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_ALPHA\n"
            "body: SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_BETA\n"
        )
        tf_path = Path(tf.name)

    try:
        result = scanner.scan_file(tf_path)
        assert result.status == YaraScanStatus.COMPLETED
        assert result.is_matched is True
        assert result.match_count == 2
        assert set(result.matched_rule_names) == {"SyntheticThreatAlpha", "SyntheticThreatBeta"}
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_scan_non_matching_file_does_not_fabricate_verdict():
    """Verify non-matching file returns is_matched=False and never manufactures a BENIGN verdict."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write("completely benign content with zero synthetic indicators")
        tf_path = Path(tf.name)

    try:
        result = scanner.scan_file(tf_path)
        assert result.status == YaraScanStatus.COMPLETED
        assert result.is_matched is False
        assert result.match_count == 0
        assert result.matched_rules == []
        assert result.matched_rule_names == []
        # CRITICAL: YARA scanner produces structured match signals, NOT a security verdict
        assert not hasattr(result, "verdict")
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_scanned_file_remains_unchanged():
    """Verify scanning is strictly read-only and does not mutate target file contents."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    content = b"Unchanged File Test \x00\x01\x02 SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_ALPHA"
    expected_hash = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
        tf.write(content)
        tf_path = Path(tf.name)

    try:
        # Pre-scan hash
        pre_hash = hashlib.sha256(tf_path.read_bytes()).hexdigest()
        assert pre_hash == expected_hash

        res = scanner.scan_file(tf_path)
        assert res.is_matched is True

        # Post-scan hash
        post_hash = hashlib.sha256(tf_path.read_bytes()).hexdigest()
        assert post_hash == expected_hash
    finally:
        if tf_path.exists():
            tf_path.unlink()


# ==============================================================================
# 3. Error Handling and Edge Cases
# ==============================================================================

def test_scan_unready_scanner_raises_scanner_not_ready():
    """Verify scanning before load_rules() raises YaraScannerNotReadyError."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    fake_path = Path(tempfile.gettempdir()) / "test.bin"
    with pytest.raises(YaraScannerNotReadyError, match="not ready"):
        scanner.scan_file(fake_path)


def test_scan_nonexistent_target_raises_not_found():
    """Verify scanning non-existent target raises FileNotFoundError."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    missing_path = Path(tempfile.gettempdir()) / f"missing_{uuid4().hex}.bin"
    with pytest.raises(FileNotFoundError, match="Target file does not exist"):
        scanner.scan_file(missing_path)


def test_scan_directory_target_raises_is_a_directory():
    """Verify scanning a directory target raises IsADirectoryError."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    with tempfile.TemporaryDirectory() as td:
        with pytest.raises(IsADirectoryError, match="Target path is a directory"):
            scanner.scan_file(td)


def test_scan_invalid_timeout_settings_rejected():
    """Verify non-positive timeout values raise ValueError."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf_path = Path(tf.name)

    try:
        with pytest.raises(ValueError, match="timeout_seconds must be a positive integer"):
            scanner.scan_file(tf_path, timeout_seconds=0)
        with pytest.raises(ValueError, match="timeout_seconds must be a positive integer"):
            scanner.scan_file(tf_path, timeout_seconds=-10)
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_scan_timeout_produces_timed_out_status_never_no_match():
    """Verify a scan timeout yields status=TIMED_OUT and is never treated as a completed no-match."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf_path = Path(tf.name)

    mock_rules = MagicMock()
    mock_rules.match.side_effect = yara.TimeoutError
    scanner._compiled_rules = mock_rules

    try:
        result = scanner.scan_file(tf_path, timeout_seconds=5)
        assert result.status == YaraScanStatus.TIMED_OUT
        assert result.timed_out is True
        assert result.is_matched is False
        assert result.match_count == 0
        assert "timed out after 5 seconds" in result.error_message
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_scan_yara_internal_error_handled_as_failed():
    """Verify unhandled YARA internal matching errors produce status=FAILED without crashing."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR)
    scanner.load_rules()

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf_path = Path(tf.name)

    mock_rules = MagicMock()
    mock_rules.match.side_effect = yara.Error("internal engine fault")
    scanner._compiled_rules = mock_rules

    try:
        result = scanner.scan_file(tf_path, timeout_seconds=5)
        assert result.status == YaraScanStatus.FAILED
        assert result.is_matched is False
        assert result.match_count == 0
        assert "internal engine fault" in result.error_message
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_scan_oversized_file_raises_too_large_error():
    """Verify file exceeding max_file_size raises YaraFileTooLargeError without scanning."""
    scanner = YaraScanner(rules_dir=FIXTURES_YARA_DIR, max_file_size=50)
    scanner.load_rules()

    with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
        tf.write(b"A" * 100)  # 100 bytes > 50 bytes limit
        tf_path = Path(tf.name)

    try:
        with pytest.raises(YaraFileTooLargeError, match="exceeds maximum configured limit"):
            scanner.scan_file(tf_path)
    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_get_default_yara_scanner_singleton():
    """Verify global default scanner instance is created safely and uninitialized."""
    s1 = get_default_yara_scanner()
    s2 = get_default_yara_scanner()
    assert s1 is s2
    assert isinstance(s1, YaraScanner)
