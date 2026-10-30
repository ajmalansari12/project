"""ONNX Runtime inference service for Sentinel-EDR LightGBM malware classifiers.

Provides production-grade inference:
- Loads compiled ONNX model artifacts via ONNX Runtime with CPU execution provider.
- Verifies model artifact integrity (SHA-256 matching metadata) and schema contracts.
- Strictly validates input tensors: float32, exactly 2,381 features, finite values (no NaN/Inf).
- Supports both single-sample and batch inference with low latency.
- Evaluates malicious and benign class probabilities and applies frozen operating thresholds.
- Distinguishes model availability and inference errors with explicit exceptions.
- Provides a structured degraded-mode response that prevents silent BENIGN misclassification.
"""

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

try:
    import onnxruntime as ort
    ONNX_RUNTIME_AVAILABLE = True
except ImportError:
    ONNX_RUNTIME_AVAILABLE = False
    ort = None

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    ModelMetadata,
)

logger = logging.getLogger("sentinel.services.onnx_inference_service")


# ==============================================================================
# Exceptions
# ==============================================================================

class OnnxInferenceError(Exception):
    """Base exception for ONNX model inference and runtime failures."""


class RuntimeDependencyError(OnnxInferenceError):
    """Raised when onnxruntime is not installed or available in the environment."""


class OnnxArtifactNotFoundError(OnnxInferenceError):
    """Raised when the specified ONNX model file does not exist on disk."""


class OnnxModelCorruptError(OnnxInferenceError):
    """Raised when the ONNX model file is invalid, truncated, or unparseable."""


class InvalidModelMetadataError(OnnxInferenceError):
    """Raised when model metadata is missing, malformed, or fails schema validation."""


class ArtifactHashMismatchError(OnnxInferenceError):
    """Raised when the computed SHA-256 digest does not match the metadata record."""


class InvalidInputDimensionError(OnnxInferenceError):
    """Raised when input features do not match the expected 2,381 dimension or tensor rank."""


class NonFiniteInputError(OnnxInferenceError):
    """Raised when input feature vectors contain NaN, positive infinity, or negative infinity."""


class InferenceExecutionError(OnnxInferenceError):
    """Raised when the underlying ONNX Runtime session execution fails."""


class InvalidInferenceOutputError(OnnxInferenceError):
    """Raised when model outputs are malformed, outside [0.0, 1.0], or have invalid shapes."""


# ==============================================================================
# Data Structures
# ==============================================================================

class ModelHealthStatus(str, Enum):
    """Operational health state of the inference service."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class InferenceResult:
    """Detailed prediction result for a single executable feature vector."""

    malicious_probability: float
    benign_probability: float
    predicted_class: str
    predicted_label: int
    operating_threshold: float
    model_id: str
    model_version: str
    inference_duration_ms: float
    is_degraded: bool = False
    degraded_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class BatchInferenceResult:
    """Aggregated prediction results for a batch of executable feature vectors."""

    results: List[InferenceResult]
    sample_count: int
    total_duration_ms: float
    average_duration_ms: float
    throughput_samples_per_sec: float
    operating_threshold: float
    model_id: str
    model_version: str
    is_degraded: bool = False
    degraded_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert batch result to dictionary representation."""
        data = asdict(self)
        data["results"] = [r.to_dict() for r in self.results]
        return data


# ==============================================================================
# ONNX Inference Service
# ==============================================================================

class OnnxInferenceService:
    """Thread-safe ONNX Runtime inference service for static PE malware classification."""

    def __init__(
        self,
        model_path: Union[str, Path],
        metadata_path: Optional[Union[str, Path]] = None,
        operating_threshold: Optional[float] = None,
        expected_features: int = EMBER_2018_CANONICAL_FEATURE_DIMENSION,
        verify_hash: bool = True,
        auto_load: bool = True,
    ) -> None:
        """Initialize the inference service.

        Args:
            model_path: Path to the compiled `.onnx` model file.
            metadata_path: Optional path to metadata JSON. If omitted, infers `<stem>_metadata.json`.
            operating_threshold: Operating decision threshold. If omitted, loaded from metadata.
            expected_features: Expected input feature dimension (default 2,381).
            verify_hash: If True, validates SHA-256 digest of artifact against metadata.
            auto_load: If True, loads the model session during initialization.
        """
        self.model_path = Path(model_path).resolve()
        if metadata_path is not None:
            self.metadata_path = Path(metadata_path).resolve()
        else:
            candidate_onnx_meta = self.model_path.parent / f"{self.model_path.stem}_onnx_metadata.json"
            if candidate_onnx_meta.is_file():
                self.metadata_path = candidate_onnx_meta
            else:
                self.metadata_path = self.model_path.parent / f"{self.model_path.stem}_metadata.json"
        self.operating_threshold = operating_threshold
        self.expected_features = expected_features
        self.verify_hash = verify_hash

        self._session: Optional["ort.InferenceSession"] = None
        self._input_name: Optional[str] = None
        self._output_names: List[str] = []
        self._prob_output_idx: int = 1
        self._metadata: Optional[Dict[str, Any]] = None
        self._model_id: str = self.model_path.stem
        self._model_version: str = "1.0.0"

        self._health_status = ModelHealthStatus.UNAVAILABLE
        self._last_error: Optional[str] = None

        if auto_load:
            self.load_model()

    @property
    def is_loaded(self) -> bool:
        """Return True if the ONNX session is initialized and healthy."""
        return self._session is not None and self._health_status == ModelHealthStatus.HEALTHY

    @property
    def health_status(self) -> ModelHealthStatus:
        """Return the current operational status of the model."""
        return self._health_status

    @property
    def model_id(self) -> str:
        """Return the model identifier."""
        return self._model_id

    @property
    def model_version(self) -> str:
        """Return the model version string."""
        return self._model_version

    @property
    def threshold(self) -> float:
        """Return the active operating threshold."""
        if self.operating_threshold is not None:
            return float(self.operating_threshold)
        return 0.8856

    def load_model(self) -> None:
        """Load, verify, and initialize the ONNX Runtime session.

        Raises:
            RuntimeDependencyError: If onnxruntime is not installed.
            OnnxArtifactNotFoundError: If the model file is not found.
            InvalidModelMetadataError: If metadata exists but cannot be parsed.
            ArtifactHashMismatchError: If the computed SHA-256 differs from metadata.
            OnnxModelCorruptError: If ONNX Runtime cannot parse the model artifact.
        """
        if not ONNX_RUNTIME_AVAILABLE:
            self._health_status = ModelHealthStatus.UNAVAILABLE
            self._last_error = "onnxruntime is not installed in the Python environment."
            raise RuntimeDependencyError(self._last_error)

        if not self.model_path.is_file():
            self._health_status = ModelHealthStatus.UNAVAILABLE
            self._last_error = f"ONNX model file not found at: {self.model_path}"
            raise OnnxArtifactNotFoundError(self._last_error)

        # 1. Load and parse metadata if present
        if self.metadata_path.is_file():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f_meta:
                    self._metadata = json.load(f_meta)
                if isinstance(self._metadata, dict):
                    self._model_id = self._metadata.get("model_id", self._model_id)
                    self._model_version = self._metadata.get("model_version", self._model_version)
                    if self.operating_threshold is None:
                        t_val = (
                            self._metadata.get("training_config", {}).get("operating_threshold")
                            or self._metadata.get("metrics", {}).get("operating_threshold")
                        )
                        if t_val is not None:
                            self.operating_threshold = float(t_val)
            except Exception as exc:
                self._health_status = ModelHealthStatus.UNAVAILABLE
                self._last_error = f"Failed to parse model metadata from {self.metadata_path}: {exc}"
                raise InvalidModelMetadataError(self._last_error) from exc

        # Default fallback threshold if none set in metadata
        if self.operating_threshold is None:
            self.operating_threshold = 0.8856

        # 2. Verify SHA-256 digest against metadata if requested
        if self.verify_hash and self._metadata and self._metadata.get("artifact_hash"):
            expected_hash = self._metadata["artifact_hash"].lower()
            hasher = hashlib.sha256()
            try:
                with open(self.model_path, "rb") as fin:
                    for chunk in iter(lambda: fin.read(65536), b""):
                        hasher.update(chunk)
                computed_hash = hasher.hexdigest().lower()
            except Exception as exc:
                self._health_status = ModelHealthStatus.UNAVAILABLE
                self._last_error = f"Failed reading model file to compute SHA-256: {exc}"
                raise OnnxModelCorruptError(self._last_error) from exc

            if computed_hash != expected_hash:
                self._health_status = ModelHealthStatus.UNAVAILABLE
                self._last_error = (
                    f"Model artifact SHA-256 mismatch for {self.model_path.name}: "
                    f"computed {computed_hash} != expected {expected_hash}"
                )
                raise ArtifactHashMismatchError(self._last_error)

        # 3. Initialize ONNX Runtime Session
        try:
            sess_opts = ort.SessionOptions()
            sess_opts.log_severity_level = 3  # Error only
            sess_opts.intra_op_num_threads = 1  # Deterministic low-jitter inference
            self._session = ort.InferenceSession(
                str(self.model_path),
                sess_options=sess_opts,
                providers=["CPUExecutionProvider"],
            )
        except Exception as exc:
            self._health_status = ModelHealthStatus.UNAVAILABLE
            self._last_error = f"ONNX Runtime failed to load model {self.model_path}: {exc}"
            raise OnnxModelCorruptError(self._last_error) from exc

        # 4. Verify input node signature
        inputs = self._session.get_inputs()
        if len(inputs) != 1:
            self._health_status = ModelHealthStatus.UNAVAILABLE
            self._last_error = f"Expected 1 model input, found {len(inputs)}: {[i.name for i in inputs]}"
            raise OnnxModelCorruptError(self._last_error)

        inp = inputs[0]
        self._input_name = inp.name
        if len(inp.shape) != 2 or inp.shape[1] != self.expected_features:
            self._health_status = ModelHealthStatus.UNAVAILABLE
            self._last_error = (
                f"Model input '{inp.name}' shape {inp.shape} does not match expected "
                f"[None, {self.expected_features}]."
            )
            raise OnnxModelCorruptError(self._last_error)

        # 5. Verify output nodes signature
        outputs = self._session.get_outputs()
        self._output_names = [o.name for o in outputs]
        if "probabilities" in self._output_names:
            self._prob_output_idx = self._output_names.index("probabilities")
        else:
            # Fallback to index 1 or 0
            self._prob_output_idx = 1 if len(self._output_names) > 1 else 0

        self._health_status = ModelHealthStatus.HEALTHY
        self._last_error = None
        logger.info(
            "ONNX model '%s' v%s loaded successfully (features: %d, threshold: %.4f)",
            self._model_id,
            self._model_version,
            self.expected_features,
            self.threshold,
        )

    def _validate_and_prepare_array(
        self,
        features: Union[np.ndarray, List[float], List[List[float]]],
    ) -> np.ndarray:
        """Validate shape, type, and finite values for input features.

        Returns:
            2D numpy array of shape (N, expected_features) with dtype float32.

        Raises:
            InvalidInputDimensionError: If feature dimension != expected_features or rank not in (1, 2).
            NonFiniteInputError: If features contain NaN, Inf, or -Inf.
        """
        try:
            arr = np.asarray(features, dtype=np.float32)
        except Exception as exc:
            raise InvalidInputDimensionError(f"Could not convert input features to float32 tensor: {exc}") from exc

        if arr.ndim == 1:
            if arr.shape[0] != self.expected_features:
                raise InvalidInputDimensionError(
                    f"Single-sample feature vector has {arr.shape[0]} dimensions; "
                    f"expected exactly {self.expected_features}."
                )
            arr = np.expand_dims(arr, axis=0)
        elif arr.ndim == 2:
            if arr.shape[1] != self.expected_features:
                raise InvalidInputDimensionError(
                    f"Batch input has {arr.shape[1]} features per record; "
                    f"expected exactly {self.expected_features}."
                )
            if arr.shape[0] == 0:
                raise InvalidInputDimensionError("Batch input contains zero records.")
        else:
            raise InvalidInputDimensionError(
                f"Input tensor must be 1D or 2D; received {arr.ndim}D tensor with shape {arr.shape}."
            )

        # Check for non-finite values (NaN / Inf)
        if not np.all(np.isfinite(arr)):
            nan_count = int(np.isnan(arr).sum())
            inf_count = int(np.isinf(arr).sum())
            raise NonFiniteInputError(
                f"Feature vector contains non-finite values ({nan_count} NaNs, {inf_count} Infs). "
                "All numerical features must be finite float32 values."
            )

        return arr

    def evaluate_probabilities(self, features_2d: np.ndarray) -> np.ndarray:
        """Run raw ONNX Runtime inference and return class probabilities.

        Args:
            features_2d: 2D numpy array of shape (N, 2381), validated float32.

        Returns:
            2D numpy array of shape (N, 2) where col 0 is benign and col 1 is malicious.

        Raises:
            InferenceExecutionError: If ONNX session execution fails.
            InvalidInferenceOutputError: If outputs are malformed.
        """
        if self._session is None or self._health_status != ModelHealthStatus.HEALTHY:
            raise InferenceExecutionError(
                f"ONNX inference session is not healthy (status: {self._health_status.value}). "
                f"Last error: {self._last_error}"
            )

        try:
            raw_outputs = self._session.run(None, {self._input_name: features_2d})
        except Exception as exc:
            raise InferenceExecutionError(f"ONNX Runtime inference execution failed: {exc}") from exc

        if len(raw_outputs) <= self._prob_output_idx:
            raise InvalidInferenceOutputError(
                f"Expected probability output at index {self._prob_output_idx}, but session returned "
                f"{len(raw_outputs)} outputs."
            )

        probs = raw_outputs[self._prob_output_idx]

        # Handle shape verification: should be (N, 2)
        if not isinstance(probs, np.ndarray) or probs.ndim != 2 or probs.shape[1] != 2:
            raise InvalidInferenceOutputError(
                f"Output probabilities must be 2D array of shape (N, 2); got {type(probs)} with shape {getattr(probs, 'shape', None)}."
            )

        if probs.shape[0] != features_2d.shape[0]:
            raise InvalidInferenceOutputError(
                f"Batch size mismatch: input had {features_2d.shape[0]} records but output has {probs.shape[0]}."
            )

        # Range check: probabilities must be between 0.0 and 1.0 (with slight numerical tolerance)
        if np.any(probs < -1e-5) or np.any(probs > 1.0 + 1e-5):
            min_val, max_val = float(np.min(probs)), float(np.max(probs))
            raise InvalidInferenceOutputError(
                f"Output probabilities out of range [0.0, 1.0]: min={min_val}, max={max_val}."
            )

        return np.clip(probs, 0.0, 1.0)

    def predict_single(
        self,
        features: Union[np.ndarray, List[float]],
        threshold: Optional[float] = None,
    ) -> InferenceResult:
        """Execute inference on a single 2,381-feature vector.

        Args:
            features: 1D array or list of 2,381 float values.
            threshold: Optional threshold override. Defaults to self.threshold.

        Returns:
            InferenceResult with probabilities, verdict, threshold, and timing.

        Raises:
            OnnxInferenceError: On invalid input, missing model, or inference failure.
        """
        arr_2d = self._validate_and_prepare_array(features)
        eff_threshold = float(threshold if threshold is not None else self.threshold)

        t_start = time.perf_counter()
        probs_2d = self.evaluate_probabilities(arr_2d)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0

        benign_prob = float(probs_2d[0, 0])
        malicious_prob = float(probs_2d[0, 1])

        # Separate raw probability inference from threshold decision logic
        is_malicious = bool(malicious_prob >= eff_threshold)
        predicted_class = "MALICIOUS" if is_malicious else "BENIGN"
        predicted_label = 1 if is_malicious else 0

        return InferenceResult(
            malicious_probability=malicious_prob,
            benign_probability=benign_prob,
            predicted_class=predicted_class,
            predicted_label=predicted_label,
            operating_threshold=eff_threshold,
            model_id=self._model_id,
            model_version=self._model_version,
            inference_duration_ms=elapsed_ms,
            is_degraded=False,
            degraded_reason=None,
        )

    def predict_batch(
        self,
        features: Union[np.ndarray, List[List[float]]],
        threshold: Optional[float] = None,
    ) -> BatchInferenceResult:
        """Execute batch inference on multiple 2,381-feature vectors.

        Args:
            features: 2D array or list of lists of shape (N, 2381).
            threshold: Optional threshold override. Defaults to self.threshold.

        Returns:
            BatchInferenceResult with per-sample InferenceResults and throughput metrics.

        Raises:
            OnnxInferenceError: On invalid input, missing model, or inference failure.
        """
        arr_2d = self._validate_and_prepare_array(features)
        n_samples = arr_2d.shape[0]
        eff_threshold = float(threshold if threshold is not None else self.threshold)

        t_start = time.perf_counter()
        probs_2d = self.evaluate_probabilities(arr_2d)
        total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

        avg_sample_ms = total_elapsed_ms / max(n_samples, 1)
        throughput = (n_samples / (total_elapsed_ms / 1000.0)) if total_elapsed_ms > 0 else 0.0

        results: List[InferenceResult] = []
        for i in range(n_samples):
            b_prob = float(probs_2d[i, 0])
            m_prob = float(probs_2d[i, 1])
            is_mal = bool(m_prob >= eff_threshold)
            results.append(
                InferenceResult(
                    malicious_probability=m_prob,
                    benign_probability=b_prob,
                    predicted_class="MALICIOUS" if is_mal else "BENIGN",
                    predicted_label=1 if is_mal else 0,
                    operating_threshold=eff_threshold,
                    model_id=self._model_id,
                    model_version=self._model_version,
                    inference_duration_ms=avg_sample_ms,
                    is_degraded=False,
                    degraded_reason=None,
                )
            )

        return BatchInferenceResult(
            results=results,
            sample_count=n_samples,
            total_duration_ms=total_elapsed_ms,
            average_duration_ms=avg_sample_ms,
            throughput_samples_per_sec=throughput,
            operating_threshold=eff_threshold,
            model_id=self._model_id,
            model_version=self._model_version,
            is_degraded=False,
            degraded_reason=None,
        )

    def get_degraded_response(
        self,
        reason: str,
        threshold: Optional[float] = None,
    ) -> InferenceResult:
        """Generate an explicit degraded-mode response.

        Never silently fabricates a BENIGN verdict. Returns predicted_class='ERROR_DEGRADED'
        with is_degraded=True and explicit degraded_reason so downstream orchestrators
        can escalate to quarantine, YARA re-scan, or manual analyst review.

        Args:
            reason: Diagnostic explanation of degraded state.
            threshold: Operating threshold for context.

        Returns:
            InferenceResult explicitly marked as degraded.
        """
        eff_threshold = float(threshold if threshold is not None else self.threshold)
        return InferenceResult(
            malicious_probability=-1.0,
            benign_probability=-1.0,
            predicted_class="ERROR_DEGRADED",
            predicted_label=-1,
            operating_threshold=eff_threshold,
            model_id=self._model_id,
            model_version=self._model_version,
            inference_duration_ms=0.0,
            is_degraded=True,
            degraded_reason=reason,
        )

    def get_health_status(self) -> Dict[str, Any]:
        """Return diagnostic health status dictionary for monitoring."""
        return {
            "status": self._health_status.value,
            "model_id": self._model_id,
            "model_version": self._model_version,
            "model_path": str(self.model_path),
            "metadata_path": str(self.metadata_path),
            "operating_threshold": self.threshold,
            "expected_features": self.expected_features,
            "is_loaded": self.is_loaded,
            "last_error": self._last_error,
        }


# ==============================================================================
# Global Default Singleton Instance
# ==============================================================================

_default_inference_service: Optional[OnnxInferenceService] = None
_service_init_lock = threading.Lock()


def get_default_onnx_inference_service() -> OnnxInferenceService:
    """Return the global default OnnxInferenceService instance.

    Lazily initializes the singleton from application settings (Design A production model).
    """
    global _default_inference_service
    if _default_inference_service is None:
        with _service_init_lock:
            if _default_inference_service is None:
                from app.core.config import get_settings

                settings = get_settings()
                _default_inference_service = OnnxInferenceService(
                    model_path=settings.ml_model_path,
                    metadata_path=settings.ml_metadata_path,
                    operating_threshold=settings.ml_operating_threshold,
                    verify_hash=settings.ml_verify_hash,
                    auto_load=True,
                )
    return _default_inference_service


def reset_default_onnx_inference_service() -> None:
    """Reset the global default OnnxInferenceService singleton (for test isolation)."""
    global _default_inference_service
    with _service_init_lock:
        _default_inference_service = None

