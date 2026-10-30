"""Analysis orchestration service coordinating detection stages for Sentinel-EDR.

In T010/T011/T016, coordinates SHA-256 hashing, local hash reputation lookup,
YARA signature scanning, and static PE LightGBM ML inference via ONNX Runtime.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import List, Optional
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.analysis_job import AnalysisJob
from app.schemas.contracts import (
    AnalysisJobStatus,
    AnalysisResult,
    HashReputationSummary,
    IncidentStatus,
    MlDetectionSummary,
    SecurityVerdict,
)
from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
)
from app.services.analysis_job_service import (
    get_analysis_job_or_raise,
    record_analysis_job_result,
    update_analysis_job_status,
)
from app.services.common import utc_now_iso
from app.services.errors import ValidationError
from app.services.evidence_service import (
    VALID_SEVERITIES,
    create_detection_evidence,
    get_detection_evidence,
)
from app.services.hash_database_service import lookup_hash
from app.services.incident_service import (
    create_incident,
    get_incident,
    get_incident_for_job,
)
from app.services.onnx_inference_service import (
    ArtifactHashMismatchError,
    InferenceExecutionError,
    InferenceResult,
    InvalidInputDimensionError,
    InvalidModelMetadataError,
    ModelHealthStatus,
    NonFiniteInputError,
    OnnxArtifactNotFoundError,
    OnnxInferenceError,
    OnnxInferenceService,
    OnnxModelCorruptError,
    RuntimeDependencyError,
    get_default_onnx_inference_service,
)
from app.services.pe_feature_extractor import (
    PEFeatureExtractionResult,
    PEFeatureExtractor,
    PEFeatureExtractorError,
    PEFileAccessError,
    PEFileNotFoundError,
    PEFileTooLargeError,
    PEIsADirectoryError,
    get_default_pe_feature_extractor,
)
from app.services.sha256_service import (
    DEFAULT_CHUNK_SIZE,
    compute_file_sha256,
    normalize_sha256,
)
from app.services.yara_scanner import (
    YaraFileAccessError,
    YaraFileTooLargeError,
    YaraRuleMatch,
    YaraScanner,
    YaraScannerNotReadyError,
    YaraScanStatus,
    YaraScanTimeoutError,
    get_default_yara_scanner,
)

logger = logging.getLogger("sentinel.services.analysis_orchestrator")


class AnalysisOrchestrator:
    """Coordinates detection analysis stages for claimed analysis jobs.

    Execution pipeline:
    1. File SHA-256 computation (via compute_file_sha256).
    2. Local hash reputation database query (via lookup_hash).
    3. YARA signature scanning (via YaraScanner) when enabled and operational.
    4. Static PE feature extraction and ONNX ML inference (ml_pe) when enabled.

    Note: Multi-engine composite risk scoring and verdict aggregation belong strictly
    to T020 and are deliberately not integrated here.
    """

    def __init__(
        self,
        *,
        chunk_size: Optional[int] = None,
        yara_scanner: Optional[YaraScanner] = None,
        yara_enabled: Optional[bool] = None,
        yara_timeout_seconds: Optional[int] = None,
        ml_service: Optional[OnnxInferenceService] = None,
        ml_enabled: Optional[bool] = None,
        pe_extractor: Optional[PEFeatureExtractor] = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            chunk_size: Optional buffer size for chunked file reading.
            yara_scanner: Optional YaraScanner instance (defaults to global default scanner).
            yara_enabled: Optional boolean override to enable/disable YARA stage.
            yara_timeout_seconds: Optional timeout in seconds for YARA scans.
            ml_service: Optional OnnxInferenceService instance (defaults to global default singleton).
            ml_enabled: Optional boolean override to enable/disable ML stage.
            pe_extractor: Optional PEFeatureExtractor instance (defaults to global default singleton).
        """
        settings = get_settings()
        self._chunk_size = chunk_size or DEFAULT_CHUNK_SIZE
        self._yara_scanner = yara_scanner
        self._yara_enabled = yara_enabled if yara_enabled is not None else settings.yara_enabled
        self._yara_timeout_seconds = (
            yara_timeout_seconds
            if yara_timeout_seconds is not None
            else settings.yara_scan_timeout_seconds
        )
        self._ml_service = ml_service
        self._ml_enabled = ml_enabled if ml_enabled is not None else settings.ml_enabled
        self._pe_extractor = pe_extractor

    def _get_scanner(self) -> YaraScanner:
        """Return the active YaraScanner instance."""
        if self._yara_scanner is not None:
            return self._yara_scanner
        return get_default_yara_scanner()

    def _get_ml_service(self) -> OnnxInferenceService:
        """Return the active OnnxInferenceService instance."""
        if self._ml_service is not None:
            return self._ml_service
        return get_default_onnx_inference_service()

    def _get_pe_extractor(self) -> PEFeatureExtractor:
        """Return the active PEFeatureExtractor instance."""
        if self._pe_extractor is not None:
            return self._pe_extractor
        return get_default_pe_feature_extractor()

    def orchestrate_job(
        self,
        session: Session,
        job_id: str,
    ) -> AnalysisResult:
        """Execute the configured analysis stages for a claimed job.

        Args:
            session: Active database session for reading and updating the job.
            job_id: Unique identifier of the analysis job to process.

        Returns:
            AnalysisResult structured contract summarizing execution findings.

        Raises:
            ResourceNotFoundError: If job_id does not exist in the database.
            ValidationError: If job is not in a valid state to be orchestrated.
        """
        job = get_analysis_job_or_raise(session, job_id)

        # Check for pre-orchestration cancellation
        if job.status == AnalysisJobStatus.CANCELLED.value:
            logger.info("Job %s was cancelled before orchestration started", job_id)
            return self._build_result(
                job_id=job.job_id,
                status=AnalysisJobStatus.CANCELLED,
                verdict=None,
                risk_score=None,
                modules_executed=[],
                modules_skipped=[],
                modules_failed=[],
            )

        if job.status != AnalysisJobStatus.IN_PROGRESS.value:
            raise ValidationError(
                f"Cannot orchestrate job {job_id} in status '{job.status}'. Expected IN_PROGRESS.",
                field="status",
            )

        logger.info("Job started [job_id=%s, file_path=%s, file_hash=%s]", job_id, job.file_path, job.file_hash)

        modules_executed: List[str] = []
        modules_skipped: List[str] = []
        modules_failed: List[str] = []
        canonical_hash: Optional[str] = None
        evidence_ids: List[UUID] = []

        # ----------------------------------------------------------------------
        # Stage 1: SHA-256 Calculation
        # ----------------------------------------------------------------------
        if job.file_path:
            try:
                canonical_hash = compute_file_sha256(job.file_path, chunk_size=self._chunk_size)
                modules_executed.append("sha256")
                logger.info("Stage completed: sha256 [job_id=%s, hash=%s]", job_id, canonical_hash)
            except (FileNotFoundError, IsADirectoryError, PermissionError, OSError, ValueError) as err:
                modules_failed.append("sha256")
                err_type = type(err).__name__
                safe_msg = f"Target file hashing failed: {err_type}"
                logger.warning("Stage failed: sha256 [job_id=%s, error=%s]", job_id, err_type)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="HASHING_FAILED",
                    error_message=safe_msg,
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                )
        elif job.file_hash:
            try:
                canonical_hash = normalize_sha256(job.file_hash)
                modules_executed.append("sha256")
                logger.info("Stage completed: sha256 normalized from input [job_id=%s, hash=%s]", job_id, canonical_hash)
            except ValidationError as err:
                modules_failed.append("sha256")
                logger.warning("Stage failed: sha256 input invalid [job_id=%s]", job_id)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="INVALID_HASH",
                    error_message=str(err),
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                )
        else:
            modules_failed.append("sha256")
            logger.warning("Stage failed: missing file_path and file_hash [job_id=%s]", job_id)
            return self._fail_job(
                session=session,
                job_id=job_id,
                error_code="INVALID_JOB_INPUT",
                error_message="Analysis job requires a valid file_path or file_hash.",
                modules_executed=modules_executed,
                modules_skipped=modules_skipped,
                modules_failed=modules_failed,
            )

        # Cooperative cancellation check between stages
        session.refresh(job)
        if job.status == AnalysisJobStatus.CANCELLED.value:
            logger.info("Job %s was cancelled during execution", job_id)
            return self._build_result(
                job_id=job.job_id,
                status=AnalysisJobStatus.CANCELLED,
                verdict=None,
                risk_score=None,
                modules_executed=modules_executed,
                modules_skipped=modules_skipped,
                modules_failed=modules_failed,
            )

        # ----------------------------------------------------------------------
        # Stage 2: Hash Reputation Lookup
        # ----------------------------------------------------------------------
        hash_reputation_summary: Optional[HashReputationSummary] = None

        try:
            lookup_result = lookup_hash(session, canonical_hash)
            modules_executed.append("hash_reputation")
            logger.info(
                "Stage completed: hash_reputation [job_id=%s, is_known=%s, verdict=%s]",
                job_id,
                lookup_result.is_known,
                lookup_result.verdict,
            )

            # Preserve exact stored reputation in structured summary.
            # Unknown hashes retain is_known=False and verdict=None without assuming BENIGN.
            hash_reputation_summary = HashReputationSummary(
                file_hash=lookup_result.file_hash,
                is_known=lookup_result.is_known,
                verdict=lookup_result.verdict,
                list_type=lookup_result.list_type,
            )

        except Exception as exc:
            modules_failed.append("hash_reputation")
            logger.exception("Stage failed: hash_reputation [job_id=%s, error=%s]", job_id, type(exc).__name__)
            return self._fail_job(
                session=session,
                job_id=job_id,
                error_code="REPUTATION_LOOKUP_FAILED",
                error_message="Hash reputation database lookup encountered an internal error.",
                modules_executed=modules_executed,
                modules_skipped=modules_skipped,
                modules_failed=modules_failed,
                file_hash=canonical_hash,
            )

        # Cooperative cancellation check between stages
        session.refresh(job)
        if job.status == AnalysisJobStatus.CANCELLED.value:
            logger.info("Job %s was cancelled during execution", job_id)
            return self._build_result(
                job_id=job.job_id,
                status=AnalysisJobStatus.CANCELLED,
                verdict=None,
                risk_score=None,
                modules_executed=modules_executed,
                modules_skipped=modules_skipped,
                modules_failed=modules_failed,
                hash_reputation=hash_reputation_summary,
            )

        # ----------------------------------------------------------------------
        # Stage 3: YARA Signature Scanning
        # ----------------------------------------------------------------------
        if not self._yara_enabled:
            modules_skipped.append("yara")
            logger.info("Stage skipped: yara [job_id=%s, reason=disabled_by_config]", job_id)
        elif not job.file_path:
            modules_skipped.append("yara")
            logger.info("Stage skipped: yara [job_id=%s, reason=no_file_path]", job_id)
        else:
            scanner = self._get_scanner()
            if not scanner.is_ready:
                modules_failed.append("yara")
                logger.warning("Stage failed: yara [job_id=%s, error=YARA_SCANNER_NOT_READY]", job_id)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_SCANNER_NOT_READY",
                    error_message="YARA scanner is not ready or rules are not compiled.",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )

            try:
                scan_result = scanner.scan_file(
                    job.file_path,
                    timeout_seconds=self._yara_timeout_seconds,
                )
            except FileNotFoundError:
                modules_failed.append("yara")
                logger.warning("Stage failed: yara file not found [job_id=%s, path=%s]", job_id, job.file_path)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_FILE_ACCESS_FAILED",
                    error_message=f"Target file not found for YARA scan: {Path(job.file_path).name}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )
            except YaraFileTooLargeError as exc:
                modules_failed.append("yara")
                logger.warning("Stage failed: yara file too large [job_id=%s, path=%s]", job_id, job.file_path)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_FILE_TOO_LARGE",
                    error_message=str(exc),
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )
            except (PermissionError, IsADirectoryError, OSError, ValueError) as exc:
                modules_failed.append("yara")
                logger.warning("Stage failed: yara file access error [job_id=%s, error=%s]", job_id, type(exc).__name__)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_FILE_ACCESS_FAILED",
                    error_message=f"Target file access failed: {type(exc).__name__}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )
            except YaraScannerNotReadyError:
                modules_failed.append("yara")
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_SCANNER_NOT_READY",
                    error_message="YARA scanner is not ready or rules are not compiled.",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )
            except YaraScanTimeoutError as exc:
                modules_failed.append("yara")
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_SCAN_TIMEOUT",
                    error_message=str(exc),
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )
            except Exception as exc:
                modules_failed.append("yara")
                logger.exception("Stage failed: unhandled yara error [job_id=%s]", job_id)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_SCAN_FAILED",
                    error_message=f"YARA scan encountered unexpected error: {type(exc).__name__}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )

            # Check scan status from result object
            if scan_result.status == YaraScanStatus.TIMED_OUT or scan_result.timed_out:
                modules_failed.append("yara")
                logger.warning("Stage failed: yara scan timed out [job_id=%s]", job_id)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_SCAN_TIMEOUT",
                    error_message=scan_result.error_message or "YARA scan timed out.",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )

            if scan_result.status == YaraScanStatus.FAILED:
                modules_failed.append("yara")
                logger.warning("Stage failed: yara scan status failed [job_id=%s, error=%s]", job_id, scan_result.error_message)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="YARA_SCAN_FAILED",
                    error_message=scan_result.error_message or "YARA scan failed.",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                )

            # Stage execution succeeded
            modules_executed.append("yara")
            logger.info(
                "Stage completed: yara [job_id=%s, is_matched=%s, match_count=%d, duration_ms=%.2f]",
                job_id,
                scan_result.is_matched,
                scan_result.match_count,
                scan_result.scan_duration_ms,
            )

            # Persist detection evidence if matched rules exist
            if scan_result.is_matched and scan_result.matched_rules:
                savepoint = session.begin_nested()
                try:
                    evidence_ids = self._persist_yara_evidence(
                        session=session,
                        job=job,
                        canonical_hash=canonical_hash,
                        matched_rules=scan_result.matched_rules,
                    )
                    savepoint.commit()
                except Exception as exc:
                    savepoint.rollback()
                    modules_executed.remove("yara")
                    modules_failed.append("yara")
                    logger.exception("Failed to persist YARA detection evidence [job_id=%s]: %s", job_id, exc)
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="EVIDENCE_PERSISTENCE_FAILED",
                        error_message="Failed to persist YARA detection evidence.",
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                    )

        # Cooperative cancellation check between stages
        session.refresh(job)
        if job.status == AnalysisJobStatus.CANCELLED.value:
            logger.info("Job %s was cancelled during execution", job_id)
            return self._build_result(
                job_id=job.job_id,
                status=AnalysisJobStatus.CANCELLED,
                verdict=None,
                risk_score=None,
                modules_executed=modules_executed,
                modules_skipped=modules_skipped,
                modules_failed=modules_failed,
                hash_reputation=hash_reputation_summary,
                evidence_ids=evidence_ids,
            )

        # ----------------------------------------------------------------------
        # Stage 4: Static PE Feature Extraction & ML Inference (ml_pe)
        # ----------------------------------------------------------------------
        ml_detection_summary: Optional[MlDetectionSummary] = None

        if not self._ml_enabled:
            modules_skipped.append("ml_pe")
            logger.info("Stage skipped: ml_pe [job_id=%s, reason=disabled_by_config]", job_id)
        elif not job.file_path:
            modules_skipped.append("ml_pe")
            logger.info("Stage skipped: ml_pe [job_id=%s, reason=no_file_path]", job_id)
        else:
            # 1. Resolve ML service
            try:
                ml_service = self._get_ml_service()
            except OnnxArtifactNotFoundError as exc:
                modules_failed.append("ml_pe")
                logger.warning("Stage failed: ML model not found [job_id=%s]: %s", job_id, exc)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="ML_MODEL_NOT_FOUND",
                    error_message=f"ONNX model artifact not found: {exc}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )
            except ArtifactHashMismatchError as exc:
                modules_failed.append("ml_pe")
                logger.warning("Stage failed: ML checksum mismatch [job_id=%s]: %s", job_id, exc)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="ML_CHECKSUM_MISMATCH",
                    error_message=f"ONNX model checksum mismatch: {exc}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )
            except (OnnxModelCorruptError, InvalidModelMetadataError) as exc:
                modules_failed.append("ml_pe")
                logger.warning("Stage failed: ML model corrupt [job_id=%s]: %s", job_id, exc)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="ML_MODEL_CORRUPT",
                    error_message=f"ONNX model file or metadata corrupt: {exc}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )
            except Exception as exc:
                modules_failed.append("ml_pe")
                logger.exception("Stage failed: ML model resolution failed [job_id=%s]: %s", job_id, exc)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="ML_MODEL_UNAVAILABLE",
                    error_message=f"ML model service resolution failed: {type(exc).__name__}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )

            if not ml_service.is_loaded or ml_service.health_status != ModelHealthStatus.HEALTHY:
                modules_failed.append("ml_pe")
                logger.warning("Stage failed: ML service not healthy [job_id=%s, status=%s]", job_id, ml_service.health_status)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="ML_MODEL_UNAVAILABLE",
                    error_message=f"ONNX model service is not healthy: {ml_service.health_status.value}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )

            # 2. Extract static PE features
            pe_extractor = self._get_pe_extractor()
            try:
                extraction_result = pe_extractor.extract_from_file(job.file_path)
            except PEFileNotFoundError as exc:
                modules_failed.append("ml_pe")
                logger.warning("Stage failed: PE file not found [job_id=%s, path=%s]", job_id, job.file_path)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="PE_FILE_ACCESS_FAILED",
                    error_message=f"Target file not found for PE feature extraction: {Path(job.file_path).name}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )
            except PEFileTooLargeError as exc:
                modules_failed.append("ml_pe")
                logger.warning("Stage failed: PE file too large [job_id=%s, path=%s]", job_id, job.file_path)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="PE_FILE_TOO_LARGE",
                    error_message=str(exc),
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )
            except (PEFileAccessError, PEIsADirectoryError, OSError, ValueError) as exc:
                modules_failed.append("ml_pe")
                logger.warning("Stage failed: PE file access error [job_id=%s, error=%s]", job_id, type(exc).__name__)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="PE_FILE_ACCESS_FAILED",
                    error_message=f"Target file access failed for PE extraction: {type(exc).__name__}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )
            except Exception as exc:
                modules_failed.append("ml_pe")
                logger.exception("Stage failed: unhandled PE extraction error [job_id=%s]", job_id)
                return self._fail_job(
                    session=session,
                    job_id=job_id,
                    error_code="PE_FEATURE_EXTRACTION_FAILED",
                    error_message=f"PE feature extraction encountered unexpected error: {type(exc).__name__}",
                    modules_executed=modules_executed,
                    modules_skipped=modules_skipped,
                    modules_failed=modules_failed,
                    file_hash=canonical_hash,
                    hash_reputation=hash_reputation_summary,
                    evidence_ids=evidence_ids,
                )

            # Check if file is an eligible PE binary
            if not extraction_result.is_pe:
                # Check whether file has MZ header (malformed PE) vs harmless non-PE file
                is_malformed_pe = False
                try:
                    with open(job.file_path, "rb") as f_head:
                        magic = f_head.read(2)
                        if magic == b"MZ" or extraction_result.parser_status == "DEGRADED_PARSE_ERROR":
                            is_malformed_pe = True
                except Exception:
                    pass

                if is_malformed_pe:
                    modules_failed.append("ml_pe")
                    logger.warning("Stage failed: malformed PE binary [job_id=%s, parser_status=%s]", job_id, extraction_result.parser_status)
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="PE_MALFORMED_FILE",
                        error_message=f"Target executable is a malformed PE binary: {extraction_result.parser_status}",
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                        evidence_ids=evidence_ids,
                    )
                else:
                    modules_skipped.append("ml_pe")
                    logger.info("Stage skipped: ml_pe [job_id=%s, reason=non_pe_file]", job_id)
            else:
                # 3. Input validation: Verify dimensions and finite values
                features = extraction_result.feature_vector.feature_values
                if len(features) != EMBER_2018_CANONICAL_FEATURE_DIMENSION:
                    modules_failed.append("ml_pe")
                    logger.warning("Stage failed: invalid feature dimensions [job_id=%s, len=%d]", job_id, len(features))
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="ML_INVALID_INPUT_DIMENSION",
                        error_message=f"Expected {EMBER_2018_CANONICAL_FEATURE_DIMENSION} features, got {len(features)}",
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                        evidence_ids=evidence_ids,
                    )

                # 4. Perform ONNX inference
                try:
                    ml_res = ml_service.predict_single(features)
                except InvalidInputDimensionError as exc:
                    modules_failed.append("ml_pe")
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="ML_INVALID_INPUT_DIMENSION",
                        error_message=str(exc),
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                        evidence_ids=evidence_ids,
                    )
                except NonFiniteInputError as exc:
                    modules_failed.append("ml_pe")
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="ML_NON_FINITE_INPUT",
                        error_message=str(exc),
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                        evidence_ids=evidence_ids,
                    )
                except (InferenceExecutionError, OnnxInferenceError) as exc:
                    modules_failed.append("ml_pe")
                    logger.exception("Stage failed: ONNX inference failed [job_id=%s]: %s", job_id, exc)
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="ML_INFERENCE_FAILED",
                        error_message=f"ONNX model inference failed: {exc}",
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                        evidence_ids=evidence_ids,
                    )
                except Exception as exc:
                    modules_failed.append("ml_pe")
                    logger.exception("Stage failed: unhandled error in ML inference [job_id=%s]: %s", job_id, exc)
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="ML_INFERENCE_FAILED",
                        error_message=f"ML inference encountered unexpected error: {type(exc).__name__}",
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                        evidence_ids=evidence_ids,
                    )

                if ml_res.is_degraded:
                    modules_failed.append("ml_pe")
                    logger.warning("Stage failed: ML returned degraded response [job_id=%s, reason=%s]", job_id, ml_res.degraded_reason)
                    return self._fail_job(
                        session=session,
                        job_id=job_id,
                        error_code="ML_INFERENCE_DEGRADED",
                        error_message=f"ML inference operating in degraded mode: {ml_res.degraded_reason}",
                        modules_executed=modules_executed,
                        modules_skipped=modules_skipped,
                        modules_failed=modules_failed,
                        file_hash=canonical_hash,
                        hash_reputation=hash_reputation_summary,
                        evidence_ids=evidence_ids,
                    )

                # Successful inference
                modules_executed.append("ml_pe")
                logger.info(
                    "Stage completed: ml_pe [job_id=%s, class=%s, mal_prob=%.4f, th=%.4f, duration_ms=%.2f]",
                    job_id,
                    ml_res.predicted_class,
                    ml_res.malicious_probability,
                    ml_res.operating_threshold,
                    ml_res.inference_duration_ms,
                )

                # Resolve artifact hash
                artifact_hash = "unknown"
                if ml_service.metadata_path and ml_service.metadata_path.is_file():
                    try:
                        with open(ml_service.metadata_path, "r", encoding="utf-8") as f_meta:
                            meta_obj = json.load(f_meta)
                            artifact_hash = meta_obj.get("artifact_hash", artifact_hash)
                    except Exception:
                        pass
                if artifact_hash == "unknown" and ml_service.model_path.is_file():
                    try:
                        artifact_hash = hashlib.sha256(ml_service.model_path.read_bytes()).hexdigest().lower()
                    except Exception:
                        pass

                ml_detection_summary = MlDetectionSummary(
                    model_id=ml_res.model_id,
                    model_version=ml_res.model_version,
                    artifact_hash=artifact_hash,
                    feature_schema=EMBER_2018_FEATURE_SCHEMA_VERSION,
                    malicious_probability=round(ml_res.malicious_probability, 6),
                    benign_probability=round(ml_res.benign_probability, 6),
                    operating_threshold=round(ml_res.operating_threshold, 6),
                    predicted_label=ml_res.predicted_label,
                    predicted_class=ml_res.predicted_class,
                    inference_duration_ms=round(ml_res.inference_duration_ms, 2),
                    is_degraded=ml_res.is_degraded,
                )

                # 5. Persist detection evidence if predicted MALICIOUS
                if ml_res.predicted_label == 1:
                    savepoint = session.begin_nested()
                    try:
                        ml_ev_ids = self._persist_ml_evidence(
                            session=session,
                            job=job,
                            canonical_hash=canonical_hash,
                            ml_result=ml_res,
                            artifact_hash=artifact_hash,
                        )
                        savepoint.commit()
                        evidence_ids.extend(ml_ev_ids)
                    except Exception as exc:
                        savepoint.rollback()
                        modules_executed.remove("ml_pe")
                        modules_failed.append("ml_pe")
                        logger.exception("Failed to persist ML detection evidence [job_id=%s]: %s", job_id, exc)
                        return self._fail_job(
                            session=session,
                            job_id=job_id,
                            error_code="EVIDENCE_PERSISTENCE_FAILED",
                            error_message="Failed to persist ML detection evidence.",
                            modules_executed=modules_executed,
                            modules_skipped=modules_skipped,
                            modules_failed=modules_failed,
                            file_hash=canonical_hash,
                            hash_reputation=hash_reputation_summary,
                            evidence_ids=evidence_ids,
                            ml_detection=ml_detection_summary,
                        )

        # Final cancellation check before committing completion
        session.refresh(job)
        if job.status == AnalysisJobStatus.CANCELLED.value:
            logger.info("Job %s was cancelled before completion", job_id)
            return self._build_result(
                job_id=job.job_id,
                status=AnalysisJobStatus.CANCELLED,
                verdict=None,
                risk_score=None,
                modules_executed=modules_executed,
                modules_skipped=modules_skipped,
                modules_failed=modules_failed,
                hash_reputation=hash_reputation_summary,
                evidence_ids=evidence_ids,
                ml_detection=ml_detection_summary,
            )

        # ----------------------------------------------------------------------
        # Finalize and Record Successful Completion
        # ----------------------------------------------------------------------
        # Top-level overall analysis verdict and risk_score remain strictly None in T011.
        # Multi-engine verdict synthesis belongs to T020 (Verdict Aggregation).
        # Stage results are preserved in hash_reputation and persisted evidence records.
        completed_at = utc_now_iso()
        record_analysis_job_result(
            session,
            job_id,
            verdict=None,
            risk_score=None,
            modules_executed=modules_executed,
            modules_skipped=modules_skipped,
            modules_failed=modules_failed,
            completed_at=completed_at,
            file_hash=canonical_hash,
        )
        update_analysis_job_status(
            session,
            job_id,
            AnalysisJobStatus.COMPLETED.value,
            completed_at=completed_at,
        )
        session.flush()

        logger.info(
            "Job completed [job_id=%s, overall_verdict=None, hash_reputation_verdict=%s, modules=%s, evidence_count=%d]",
            job_id,
            hash_reputation_summary.verdict if hash_reputation_summary else None,
            modules_executed,
            len(evidence_ids),
        )

        return self._build_result(
            job_id=job_id,
            status=AnalysisJobStatus.COMPLETED,
            verdict=None,
            risk_score=None,
            modules_executed=modules_executed,
            modules_skipped=modules_skipped,
            modules_failed=modules_failed,
            hash_reputation=hash_reputation_summary,
            evidence_ids=evidence_ids,
            ml_detection=ml_detection_summary,
        )

    def _persist_yara_evidence(
        self,
        session: Session,
        job: AnalysisJob,
        canonical_hash: Optional[str],
        matched_rules: List[YaraRuleMatch],
    ) -> List[UUID]:
        """Persist structured DetectionEvidence for matching YARA rules.

        Ensures associated Incident exists to satisfy foreign key constraints,
        and uses deterministic evidence UUIDs to guarantee idempotent execution.

        Args:
            session: Active database session.
            job: Current AnalysisJob model instance.
            canonical_hash: Normalized file SHA-256 digest, if computed.
            matched_rules: List of YaraRuleMatch objects to record.

        Returns:
            List of persisted evidence UUIDs.
        """
        # 1. Resolve or create associated Incident to satisfy foreign key requirement
        incident = get_incident_for_job(session, job.job_id)

        if incident is None:
            file_name = Path(job.file_path).name if job.file_path else "target_file"
            matched_names = ", ".join(r.rule_name for r in matched_rules)
            incident_uuid = uuid5(NAMESPACE_URL, f"sentinel:incident:{job.job_id}")
            incident = get_incident(session, str(incident_uuid))
            if incident is None:
                incident = create_incident(
                    session,
                    incident_id=str(incident_uuid),
                    analysis_job_id=job.job_id,
                    title=f"Signature detection on {file_name}",
                    incident_type="SIGNATURE_DETECTION",
                    verdict=SecurityVerdict.SUSPICIOUS.value,
                    risk_score=50.0,
                    status=IncidentStatus.OPEN.value,
                    file_path=job.file_path,
                    file_hash=canonical_hash or job.file_hash,
                    description=f"YARA signature rules matched: {matched_names}",
                )

        # 2. Persist detection evidence for each matched rule idempotently via established evidence service
        persisted_evidence_ids: List[UUID] = []
        now_iso = utc_now_iso()

        for rule in matched_rules:
            # Deterministic UUID for idempotency
            evidence_uuid = uuid5(
                NAMESPACE_URL,
                f"sentinel:evidence:{job.job_id}:yara:{rule.namespace}:{rule.rule_name}",
            )
            existing = get_detection_evidence(session, str(evidence_uuid))
            if existing is not None:
                persisted_evidence_ids.append(evidence_uuid)
                continue

            # Extract severity from rule metadata if present and valid
            raw_sev = str(rule.metadata.get("severity", "HIGH")).upper()
            severity = raw_sev if raw_sev in VALID_SEVERITIES else "HIGH"

            description = rule.metadata.get(
                "description",
                f"YARA signature rule '{rule.rule_name}' matched in namespace '{rule.namespace}'",
            )
            observed_val = (
                f"{len(rule.matched_strings)} string match(es)"
                if rule.matched_strings
                else f"Rule {rule.rule_name}"
            )

            details = {
                "rule_name": rule.rule_name,
                "namespace": rule.namespace,
                "tags": list(rule.tags),
                "metadata": dict(rule.metadata),
                "matched_strings_count": len(rule.matched_strings),
            }

            create_detection_evidence(
                session,
                evidence_id=str(evidence_uuid),
                incident_id=incident.incident_id,
                analysis_job_id=job.job_id,
                source="yara",
                indicator=f"{rule.namespace}:{rule.rule_name}",
                severity=severity,
                description=description,
                observed_value=observed_val,
                confidence=1.0,
                score_contribution=None,  # Scoring is strictly deferred to T020
                details=details,
                observed_at=now_iso,
            )
            persisted_evidence_ids.append(evidence_uuid)

        return persisted_evidence_ids

    def _persist_ml_evidence(
        self,
        session: Session,
        job: AnalysisJob,
        canonical_hash: Optional[str],
        ml_result: InferenceResult,
        artifact_hash: str,
    ) -> List[UUID]:
        """Persist structured DetectionEvidence for static PE ML detection.

        Ensures associated Incident exists to satisfy foreign key constraints,
        and uses deterministic evidence UUIDs to guarantee idempotent execution.

        Args:
            session: Active database session.
            job: Current AnalysisJob model instance.
            canonical_hash: Normalized file SHA-256 digest, if computed.
            ml_result: InferenceResult output from OnnxInferenceService.
            artifact_hash: SHA-256 digest of the evaluated model artifact.

        Returns:
            List of persisted evidence UUIDs.
        """
        # 1. Resolve or create associated Incident to satisfy foreign key requirement
        incident = get_incident_for_job(session, job.job_id)

        if incident is None:
            file_name = Path(job.file_path).name if job.file_path else "target_file"
            incident_uuid = uuid5(NAMESPACE_URL, f"sentinel:incident:{job.job_id}")
            incident = get_incident(session, str(incident_uuid))
            if incident is None:
                incident = create_incident(
                    session,
                    incident_id=str(incident_uuid),
                    analysis_job_id=job.job_id,
                    title=f"Static ML malware detection on {file_name}",
                    incident_type="ML_DETECTION",
                    verdict=SecurityVerdict.SUSPICIOUS.value,
                    risk_score=50.0,
                    status=IncidentStatus.OPEN.value,
                    file_path=job.file_path,
                    file_hash=canonical_hash or job.file_hash,
                    description=(
                        f"Static PE classifier '{ml_result.model_id}' flagged executable as "
                        f"{ml_result.predicted_class} (P(Malicious)={ml_result.malicious_probability:.4f} >= "
                        f"{ml_result.operating_threshold:.4f})"
                    ),
                )

        # 2. Persist detection evidence idempotently
        now_iso = utc_now_iso()
        evidence_uuid = uuid5(
            NAMESPACE_URL,
            f"sentinel:evidence:{job.job_id}:ml:{ml_result.model_id}:{ml_result.model_version}",
        )
        existing = get_detection_evidence(session, str(evidence_uuid))
        if existing is not None:
            return [evidence_uuid]

        severity = "HIGH" if ml_result.predicted_label == 1 else "INFO"
        description = (
            f"Static PE LightGBM classifier '{ml_result.model_id}' v{ml_result.model_version} "
            f"classified file as {ml_result.predicted_class} with malicious probability "
            f"{ml_result.malicious_probability:.4f} (operating threshold {ml_result.operating_threshold:.4f})"
        )
        observed_val = f"P(Malicious)={ml_result.malicious_probability:.4f}"

        details = {
            "file_hash": canonical_hash or job.file_hash,
            "source": "MACHINE_LEARNING",
            "detection_source": "MACHINE_LEARNING",
            "model_id": ml_result.model_id,
            "model_version": ml_result.model_version,
            "artifact_hash": artifact_hash,
            "feature_schema": EMBER_2018_FEATURE_SCHEMA_VERSION,
            "malicious_probability": round(ml_result.malicious_probability, 6),
            "benign_probability": round(ml_result.benign_probability, 6),
            "operating_threshold": round(ml_result.operating_threshold, 6),
            "predicted_label": ml_result.predicted_label,
            "predicted_class": ml_result.predicted_class,
            "inference_duration_ms": round(ml_result.inference_duration_ms, 2),
            "analysis_job_id": job.job_id,
            "observed_at": now_iso,
        }

        create_detection_evidence(
            session,
            evidence_id=str(evidence_uuid),
            incident_id=incident.incident_id,
            analysis_job_id=job.job_id,
            source="ml_pe",
            indicator=f"{ml_result.model_id}:{ml_result.model_version}",
            severity=severity,
            description=description,
            observed_value=observed_val,
            confidence=round(ml_result.malicious_probability, 4),
            score_contribution=None,  # Scoring is strictly deferred to T020
            details=details,
            observed_at=now_iso,
        )

        return [evidence_uuid]

    def _fail_job(
        self,
        session: Session,
        job_id: str,
        error_code: str,
        error_message: str,
        modules_executed: List[str],
        modules_skipped: List[str],
        modules_failed: List[str],
        file_hash: Optional[str] = None,
        hash_reputation: Optional[HashReputationSummary] = None,
        evidence_ids: Optional[List[UUID]] = None,
        ml_detection: Optional[MlDetectionSummary] = None,
    ) -> AnalysisResult:
        """Helper to mark job FAILED, record telemetry, and return structured result."""
        completed_at = utc_now_iso()
        record_analysis_job_result(
            session,
            job_id,
            verdict=None,
            risk_score=None,
            modules_executed=modules_executed,
            modules_skipped=modules_skipped,
            modules_failed=modules_failed,
            completed_at=completed_at,
            file_hash=file_hash,
        )
        update_analysis_job_status(
            session,
            job_id,
            AnalysisJobStatus.FAILED.value,
            error_code=error_code,
            error_message=error_message,
            completed_at=completed_at,
        )
        session.flush()
        logger.warning("Job failed [job_id=%s, error_code=%s, error_message=%s]", job_id, error_code, error_message)

        return self._build_result(
            job_id=job_id,
            status=AnalysisJobStatus.FAILED,
            verdict=None,
            risk_score=None,
            modules_executed=modules_executed,
            modules_skipped=modules_skipped,
            modules_failed=modules_failed,
            hash_reputation=hash_reputation,
            evidence_ids=evidence_ids,
            ml_detection=ml_detection,
        )

    def _build_result(
        self,
        job_id: str,
        status: AnalysisJobStatus,
        verdict: Optional[SecurityVerdict],
        risk_score: Optional[float],
        modules_executed: List[str],
        modules_skipped: List[str],
        modules_failed: List[str],
        hash_reputation: Optional[HashReputationSummary] = None,
        evidence_ids: Optional[List[UUID]] = None,
        ml_detection: Optional[MlDetectionSummary] = None,
    ) -> AnalysisResult:
        """Construct a validated AnalysisResult contract instance."""
        return AnalysisResult(
            job_id=UUID(job_id),
            analysis_status=status,
            verdict=verdict,
            risk_score=risk_score,
            modules_executed=modules_executed,
            modules_skipped=modules_skipped,
            modules_failed=modules_failed,
            evidence_ids=evidence_ids or [],
            hash_reputation=hash_reputation,
            ml_detection=ml_detection,
        )
