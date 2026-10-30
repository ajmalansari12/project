"""Sentinel-EDR persistence and domain service layer."""

from app.services.analysis_job_service import (
    cancel_analysis_job,
    claim_analysis_job,
    create_analysis_job,
    get_analysis_job,
    get_analysis_job_or_raise,
    get_pending_queued_job_ids,
    list_analysis_jobs,
    record_analysis_job_result,
    recover_interrupted_jobs,
    update_analysis_job_status,
)
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.analysis_queue import AnalysisQueue
from app.services.analysis_worker import (
    AnalysisWorker,
    AnalysisWorkerManager,
    get_default_analysis_queue,
    get_default_worker_manager,
    reset_worker_manager,
)
from app.services.audit_service import (
    append_audit_log,
    get_audit_log,
    get_audit_log_or_raise,
    list_audit_logs,
)
from app.services.common import PaginatedResult, paginate_query, utc_now_iso
from app.services.dataset_validator import (
    DatasetValidationReport,
    DatasetValidator,
)
from app.services.ember_dataset_service import (
    EmberArchiveSecurityError,
    EmberChecksumMismatchError,
    EmberDatasetError,
    EmberDatasetNotFoundError,
    EmberDatasetService,
    IngestionSummary,
)
from app.services.ember_raw_vectorizer import (
    EmberMalformedRecordError,
    EmberNonFiniteValueError,
    EmberRawFeatureVectorizer,
    EmberVectorizerError,
    get_default_ember_raw_vectorizer,
)
from app.services.endpoint_event_service import (
    create_endpoint_event,
    get_endpoint_event,
    get_endpoint_event_or_raise,
    list_endpoint_events,
)
from app.services.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)
from app.services.evidence_service import (
    create_detection_evidence,
    get_detection_evidence,
    get_detection_evidence_or_raise,
    list_evidence_for_incident,
    list_evidence_for_job,
)
from app.services.forensic_report_service import (
    create_forensic_report,
    get_forensic_report,
    get_forensic_report_or_raise,
    list_reports_for_incident,
    update_forensic_report_status,
)
from app.services.hash_database_service import (
    HashLookupResult,
    create_hash_reputation,
    delete_hash_reputation,
    get_hash_reputation,
    list_hash_reputations,
    lookup_hash,
    upsert_hash_reputation,
)
from app.services.incident_service import (
    create_incident,
    get_incident,
    get_incident_for_job,
    get_incident_or_raise,
    list_incidents,
    update_incident_status,
)
from app.services.lightgbm_training import (
    DEFAULT_LIGHTGBM_PARAMS,
    EvaluationMetricError,
    EvaluationReport,
    InsufficientClassDataError,
    LightGBMTrainer,
    ModelTrainingError,
)
from app.services.onnx_export_service import (
    InvalidModelSchemaError,
    LightGBMModelLoadError,
    OnnxConversionError,
    OnnxDependencyError,
    OnnxExportError,
    OnnxExportValidationError,
    OnnxModelExporter,
)
from app.services.onnx_inference_service import (
    ArtifactHashMismatchError,
    BatchInferenceResult,
    InferenceExecutionError,
    InferenceResult,
    InvalidInferenceOutputError,
    InvalidInputDimensionError,
    InvalidModelMetadataError,
    ModelHealthStatus,
    NonFiniteInputError,
    OnnxArtifactNotFoundError,
    OnnxInferenceError,
    OnnxInferenceService,
    OnnxModelCorruptError,
    RuntimeDependencyError,
)
from app.services.pe_feature_extractor import (
    EXTRACTOR_IMPLEMENTATION_VERSION,
    GROUP_DIMENSIONS,
    PEFeatureExtractionResult,
    PEFeatureExtractor,
    PEFeatureExtractorError,
    PEFileAccessError,
    PEFileNotFoundError,
    PEFileTooLargeError,
    PEIsADirectoryError,
    PEMalformedFileError,
    TESTED_LIEF_VERSION,
    TESTED_NUMPY_VERSION,
    TESTED_SKLEARN_VERSION,
    extract_pe_features,
    extract_pe_features_from_bytes,
    get_default_pe_feature_extractor,
)
from app.services.quarantine_service import (
    create_quarantine_record,
    get_quarantine_record,
    get_quarantine_record_or_raise,
    list_quarantine_records,
    update_quarantine_status,
)
from app.services.response_action_service import (
    create_response_action,
    get_response_action,
    get_response_action_or_raise,
    list_response_actions_for_incident,
    update_response_action_status,
)
from app.services.sha256_service import (
    DEFAULT_CHUNK_SIZE,
    EMPTY_FILE_SHA256,
    compute_bytes_sha256,
    compute_file_sha256,
    is_valid_sha256,
    normalize_sha256,
)
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
    YaraStringMatch,
    get_default_yara_scanner,
    reset_default_yara_scanner,
)

__all__ = [
    # Errors
    "PersistenceError",
    "ResourceNotFoundError",
    "PersistenceConflictError",
    "InvalidStateTransitionError",
    "ValidationError",
    # Common
    "PaginatedResult",
    "paginate_query",
    "utc_now_iso",
    # Dataset Validation
    "DatasetValidationReport",
    "DatasetValidator",
    # Endpoint Event Service
    "create_endpoint_event",
    "get_endpoint_event",
    "get_endpoint_event_or_raise",
    "list_endpoint_events",
    # Analysis Job Service
    "create_analysis_job",
    "get_analysis_job",
    "get_analysis_job_or_raise",
    "list_analysis_jobs",
    "update_analysis_job_status",
    "record_analysis_job_result",
    "claim_analysis_job",
    "cancel_analysis_job",
    "recover_interrupted_jobs",
    "get_pending_queued_job_ids",
    # Analysis Queue, Orchestrator, and Worker
    "AnalysisQueue",
    "AnalysisOrchestrator",
    "AnalysisWorker",
    "AnalysisWorkerManager",
    "get_default_analysis_queue",
    "get_default_worker_manager",
    "reset_worker_manager",
    # Incident Service
    "create_incident",
    "get_incident",
    "get_incident_for_job",
    "get_incident_or_raise",
    "list_incidents",
    "update_incident_status",
    # Evidence Service
    "create_detection_evidence",
    "get_detection_evidence",
    "get_detection_evidence_or_raise",
    "list_evidence_for_incident",
    "list_evidence_for_job",
    # Response Action Service
    "create_response_action",
    "get_response_action",
    "get_response_action_or_raise",
    "list_response_actions_for_incident",
    "update_response_action_status",
    # Quarantine Service
    "create_quarantine_record",
    "get_quarantine_record",
    "get_quarantine_record_or_raise",
    "list_quarantine_records",
    "update_quarantine_status",
    # Forensic Report Service
    "create_forensic_report",
    "get_forensic_report",
    "get_forensic_report_or_raise",
    "list_reports_for_incident",
    "update_forensic_report_status",
    # PE Feature Extractor Service
    "PEFeatureExtractor",
    "PEFeatureExtractionResult",
    "PEFeatureExtractorError",
    "PEFileNotFoundError",
    "PEIsADirectoryError",
    "PEFileAccessError",
    "PEFileTooLargeError",
    "PEMalformedFileError",
    "extract_pe_features",
    "extract_pe_features_from_bytes",
    "get_default_pe_feature_extractor",
    "GROUP_DIMENSIONS",
    "EXTRACTOR_IMPLEMENTATION_VERSION",
    "TESTED_LIEF_VERSION",
    "TESTED_NUMPY_VERSION",
    "TESTED_SKLEARN_VERSION",
    # Audit Service
    "append_audit_log",
    "get_audit_log",
    "get_audit_log_or_raise",
    "list_audit_logs",
    # SHA-256 Service
    "DEFAULT_CHUNK_SIZE",
    "EMPTY_FILE_SHA256",
    "compute_file_sha256",
    "compute_bytes_sha256",
    "is_valid_sha256",
    "normalize_sha256",
    # Hash Database Service
    "HashLookupResult",
    "lookup_hash",
    "create_hash_reputation",
    "upsert_hash_reputation",
    "get_hash_reputation",
    "list_hash_reputations",
    "delete_hash_reputation",
    # YARA Scanner Service
    "YaraScanner",
    "YaraScannerState",
    "YaraScanStatus",
    "YaraScanResult",
    "YaraRuleMatch",
    "YaraStringMatch",
    "YaraScannerError",
    "YaraScannerNotReadyError",
    "YaraRuleCompilationError",
    "YaraScanTimeoutError",
    "YaraFileAccessError",
    "YaraFileTooLargeError",
    "get_default_yara_scanner",
    "reset_default_yara_scanner",
    # EMBER Raw Feature Vectorization (T014)
    "EmberRawFeatureVectorizer",
    "get_default_ember_raw_vectorizer",
    "EmberVectorizerError",
    "EmberMalformedRecordError",
    "EmberNonFiniteValueError",
    # EMBER Dataset Service (T014)
    "EmberDatasetService",
    "EmberDatasetError",
    "EmberChecksumMismatchError",
    "EmberArchiveSecurityError",
    "EmberDatasetNotFoundError",
    "IngestionSummary",
    # LightGBM Training & Evaluation (T014)
    "LightGBMTrainer",
    "EvaluationReport",
    "ModelTrainingError",
    "InsufficientClassDataError",
    "EvaluationMetricError",
    "DEFAULT_LIGHTGBM_PARAMS",
    # ONNX Export Service (T015)
    "OnnxModelExporter",
    "OnnxExportError",
    "OnnxDependencyError",
    "LightGBMModelLoadError",
    "InvalidModelSchemaError",
    "OnnxConversionError",
    "OnnxExportValidationError",
    # ONNX Inference Service (T015)
    "OnnxInferenceService",
    "OnnxInferenceError",
    "RuntimeDependencyError",
    "OnnxArtifactNotFoundError",
    "OnnxModelCorruptError",
    "InvalidModelMetadataError",
    "ArtifactHashMismatchError",
    "InvalidInputDimensionError",
    "NonFiniteInputError",
    "InferenceExecutionError",
    "InvalidInferenceOutputError",
    "ModelHealthStatus",
    "InferenceResult",
    "BatchInferenceResult",
]
