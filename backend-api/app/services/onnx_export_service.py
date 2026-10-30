"""ONNX model export service for Sentinel-EDR LightGBM malware classifiers.

Converts trained LightGBM binary classification models to ONNX format:
- Preserves the canonical 2,381-feature float32 input tensor schema ('ember_pe_v2').
- Preserves binary classification probability outputs ('label' and 'probabilities').
- Enforces dynamic batch dimensions on both input and outputs.
- Validates exported ONNX graph input/output signatures through ONNX Runtime.
- Persists ONNX artifacts atomically with SHA-256 verification and ModelMetadata.
- Preserves existing valid artifacts if export fails.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

import lightgbm as lgb
import numpy as np

try:
    import onnx
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    onnx = None
    convert_lightgbm = None
    FloatTensorType = None
    ort = None

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_DATASET_NAME,
    EMBER_2018_DATASET_VERSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
    ModelFamily,
    ModelMetadata,
    ModelMetrics,
    TaskType,
)

logger = logging.getLogger("sentinel.services.onnx_export_service")


# ==============================================================================
# ONNX Export Exceptions
# ==============================================================================

class OnnxExportError(Exception):
    """Base exception for ONNX model export and validation errors."""


class OnnxDependencyError(OnnxExportError):
    """Raised when required ONNX conversion libraries are not available."""


class LightGBMModelLoadError(OnnxExportError):
    """Raised when the source LightGBM model file cannot be loaded or is corrupt."""


class InvalidModelSchemaError(OnnxExportError):
    """Raised when the booster does not match the expected 2,381-feature input schema."""


class OnnxConversionError(OnnxExportError):
    """Raised when the underlying converter fails to generate an ONNX graph."""


class OnnxExportValidationError(OnnxExportError):
    """Raised when the exported ONNX model fails structural or session validation."""


def _safe_atomic_persist(temp_path: Path, dest_path: Path) -> None:
    """Atomically or safely move a temporary file to its final destination."""
    try:
        if dest_path.exists():
            dest_path.unlink()
        temp_path.replace(dest_path)
    except OSError:
        # Fallback for Windows AppContainer / NTFS file locks
        shutil.copyfile(temp_path, dest_path)
        try:
            temp_path.unlink()
        except OSError:
            pass


# ==============================================================================
# ONNX Model Exporter
# ==============================================================================

class OnnxModelExporter:
    """Service for converting LightGBM PE malware classification models to ONNX."""

    def __init__(
        self,
        feature_count: int = EMBER_2018_CANONICAL_FEATURE_DIMENSION,
        target_opset: int = 15,
        input_name: str = "features",
    ) -> None:
        """Initialize the ONNX exporter with validated feature dimension and opset.

        Args:
            feature_count: Expected feature count (defaults to canonical 2,381).
            target_opset: Target ONNX operator set version (defaults to 15).
            input_name: Name of the input tensor node in the ONNX graph.
        """
        self.feature_count = feature_count
        self.target_opset = target_opset
        self.input_name = input_name

    def _ensure_dependencies(self) -> None:
        """Verify that ONNX conversion libraries are installed."""
        if not ONNX_AVAILABLE:
            raise OnnxDependencyError(
                "Required ONNX packages ('onnx', 'onnxmltools', 'onnxruntime') are not installed. "
                "Install them via requirements.txt."
            )

    def load_booster(self, model_file: Union[str, Path]) -> lgb.Booster:
        """Load and validate a LightGBM Booster from a text or binary file.

        Args:
            model_file: Path to the LightGBM model file.

        Returns:
            Validated lgb.Booster instance.

        Raises:
            LightGBMModelLoadError: If file is missing or corrupt.
            InvalidModelSchemaError: If feature count does not match expected schema.
        """
        path = Path(model_file)
        if not path.is_file():
            raise LightGBMModelLoadError(f"LightGBM model file does not exist: {path}")

        try:
            booster = lgb.Booster(model_file=str(path))
        except Exception as exc:
            raise LightGBMModelLoadError(
                f"Failed to load LightGBM booster from {path}: {exc}"
            ) from exc

        num_features = booster.num_feature()
        if num_features != self.feature_count:
            raise InvalidModelSchemaError(
                f"Model feature count ({num_features}) does not match expected "
                f"feature schema dimension ({self.feature_count})."
            )

        return booster

    def convert_booster_to_onnx(
        self,
        booster: lgb.Booster,
        name: str = "sentinel_pe_classifier",
    ) -> "onnx.ModelProto":
        """Convert a LightGBM Booster into a validated ONNX ModelProto with dynamic batch shapes.

        Args:
            booster: Trained LightGBM booster.
            name: Optional model graph name.

        Returns:
            Validated onnx.ModelProto instance.

        Raises:
            OnnxDependencyError: If dependencies are missing.
            InvalidModelSchemaError: If input booster has unexpected feature count.
            OnnxConversionError: If conversion fails.
            OnnxExportValidationError: If graph structure is invalid.
        """
        self._ensure_dependencies()

        num_features = booster.num_feature()
        if num_features != self.feature_count:
            raise InvalidModelSchemaError(
                f"Booster feature count ({num_features}) does not match {self.feature_count}."
            )

        initial_types = [(self.input_name, FloatTensorType([None, self.feature_count]))]

        try:
            onnx_model = convert_lightgbm(
                booster,
                name=name,
                initial_types=initial_types,
                target_opset=self.target_opset,
                zipmap=False,
            )
        except Exception as exc:
            raise OnnxConversionError(f"LightGBM-to-ONNX conversion failed: {exc}") from exc

        # Fix dynamic batch dimension on label output to prevent runtime shape mismatch warning:
        # onnxmltools by default emits output 'label' with fixed shape [1].
        # Clearing dim_value and setting dim_param = 'None' enables dynamic batch size.
        try:
            for out in onnx_model.graph.output:
                if out.name == "label":
                    shape = out.type.tensor_type.shape
                    if len(shape.dim) > 0:
                        shape.dim[0].ClearField("dim_value")
                        shape.dim[0].dim_param = "None"
        except Exception as exc:
            logger.warning("Could not adjust dynamic batch parameter on label output: %s", exc)

        # Validate graph with onnx.checker
        try:
            onnx.checker.check_model(onnx_model)
        except Exception as exc:
            raise OnnxExportValidationError(f"Exported ONNX model failed structural check: {exc}") from exc

        # Validate that ONNX Runtime can successfully initialize and execute a dummy inference pass
        self._validate_onnx_runtime_session(onnx_model)

        return onnx_model

    def _validate_onnx_runtime_session(self, onnx_model: "onnx.ModelProto") -> None:
        """Validate that the exported ONNX model loads cleanly in ONNX Runtime and outputs valid shapes."""
        try:
            model_bytes = onnx_model.SerializeToString()
            opts = ort.SessionOptions()
            opts.log_severity_level = 3  # Error only
            session = ort.InferenceSession(model_bytes, sess_options=opts, providers=["CPUExecutionProvider"])
        except Exception as exc:
            raise OnnxExportValidationError(
                f"ONNX Runtime failed to initialize inference session from exported model: {exc}"
            ) from exc

        # Verify inputs
        inputs = session.get_inputs()
        if len(inputs) != 1:
            raise OnnxExportValidationError(f"Expected exactly 1 input tensor, got {len(inputs)}.")
        inp = inputs[0]
        if inp.name != self.input_name:
            logger.info("ONNX model input name is '%s' (expected '%s')", inp.name, self.input_name)
        if len(inp.shape) != 2 or inp.shape[1] != self.feature_count:
            raise OnnxExportValidationError(
                f"Input tensor shape mismatch: expected [None, {self.feature_count}], got {inp.shape}."
            )

        # Verify outputs
        outputs = session.get_outputs()
        output_names = [o.name for o in outputs]
        if "probabilities" not in output_names:
            raise OnnxExportValidationError(
                f"Required output 'probabilities' missing from model outputs: {output_names}."
            )

        # Execute dummy test pass with shape (2, feature_count)
        dummy_input = np.zeros((2, self.feature_count), dtype=np.float32)
        try:
            raw_out = session.run(None, {inp.name: dummy_input})
        except Exception as exc:
            raise OnnxExportValidationError(f"Test inference pass failed on dummy input: {exc}") from exc

        prob_idx = output_names.index("probabilities")
        probs = raw_out[prob_idx]
        if probs.shape != (2, 2):
            raise OnnxExportValidationError(
                f"Expected probability tensor shape (2, 2) for batch of 2, got {probs.shape}."
            )
        if np.any(np.isnan(probs)) or np.any(np.isinf(probs)):
            raise OnnxExportValidationError("Dummy inference returned non-finite probabilities.")

    def export_booster_to_file(
        self,
        booster: lgb.Booster,
        output_onnx_path: Union[str, Path],
        metadata_path: Optional[Union[str, Path]] = None,
        source_metadata_path: Optional[Union[str, Path]] = None,
        operating_threshold: Optional[float] = None,
        model_id: Optional[str] = None,
        model_version: Optional[str] = None,
    ) -> Tuple[Path, Path, ModelMetadata]:
        """Convert and atomically write an ONNX model file and its validated ModelMetadata.

        Args:
            booster: Trained LightGBM booster.
            output_onnx_path: Destination path for the `.onnx` file.
            metadata_path: Destination path for the metadata JSON (defaults to `<stem>_metadata.json`).
            source_metadata_path: Optional path to T014 LightGBM metadata JSON to copy training provenance.
            operating_threshold: Operating decision threshold (e.g. 0.8856 for Design A).
            model_id: Identifier for the model (defaults to output file stem).
            model_version: Semantic version string (defaults to '1.0.0').

        Returns:
            Tuple of (final_onnx_path, final_metadata_path, ModelMetadata_instance).
        """
        self._ensure_dependencies()

        dest_onnx = Path(output_onnx_path).resolve()
        dest_onnx.parent.mkdir(parents=True, exist_ok=True)

        if metadata_path is not None:
            dest_meta = Path(metadata_path).resolve()
        else:
            dest_meta = dest_onnx.parent / f"{dest_onnx.stem}_onnx_metadata.json"
        dest_meta.parent.mkdir(parents=True, exist_ok=True)

        # Convert booster to ONNX
        onnx_model = self.convert_booster_to_onnx(booster, name=dest_onnx.stem)

        # 1. Atomic write of ONNX artifact using temp file in target directory
        temp_onnx = dest_onnx.parent / f"{dest_onnx.name}.tmp"
        try:
            with open(temp_onnx, "wb") as f_out:
                f_out.write(onnx_model.SerializeToString())

            # Compute canonical SHA-256
            hasher = hashlib.sha256()
            with open(temp_onnx, "rb") as f_in:
                for chunk in iter(lambda: f_in.read(65536), b""):
                    hasher.update(chunk)
            artifact_hash = hasher.hexdigest().lower()

            # Atomically replace target ONNX file
            _safe_atomic_persist(temp_onnx, dest_onnx)
        except Exception as exc:
            if temp_onnx.exists():
                try:
                    temp_onnx.unlink()
                except OSError:
                    pass
            raise OnnxExportError(f"Failed to atomically persist ONNX artifact to {dest_onnx}: {exc}") from exc

        # 2. Assemble ModelMetadata
        source_meta: Optional[Dict[str, Any]] = None
        if source_metadata_path is not None:
            s_path = Path(source_metadata_path)
            if s_path.is_file():
                try:
                    with open(s_path, "r", encoding="utf-8") as sf:
                        source_meta = json.load(sf)
                except Exception as exc:
                    logger.warning("Could not read source metadata from %s: %s", s_path, exc)

        eff_model_id = model_id or (source_meta.get("model_id") if source_meta else dest_onnx.stem)
        eff_version = model_version or (source_meta.get("model_version") if source_meta else "1.0.0")

        # Threshold priority: explicit arg > source metadata > default 0.8856
        eff_threshold = operating_threshold
        if eff_threshold is None and source_meta:
            eff_threshold = (
                source_meta.get("training_config", {}).get("operating_threshold")
                or source_meta.get("metrics", {}).get("operating_threshold")
            )
        if eff_threshold is None:
            eff_threshold = 0.8856

        training_cfg: Dict[str, Any] = {
            "onnx_target_opset": self.target_opset,
            "onnx_input_name": self.input_name,
            "onnx_converter": "onnxmltools",
            "operating_threshold": float(eff_threshold),
        }
        if source_meta and "training_config" in source_meta and isinstance(source_meta["training_config"], dict):
            training_cfg.update(source_meta["training_config"])
            training_cfg["operating_threshold"] = float(eff_threshold)

        metrics_obj: Optional[ModelMetrics] = None
        if source_meta and "metrics" in source_meta and isinstance(source_meta["metrics"], dict):
            m_data = source_meta["metrics"]
            metrics_obj = ModelMetrics(
                roc_auc=m_data.get("roc_auc"),
                precision=m_data.get("precision"),
                recall=m_data.get("recall"),
                f1_score=m_data.get("f1_score"),
                false_positive_rate=m_data.get("false_positive_rate"),
                evaluation_split=m_data.get("evaluation_split", "test"),
            )

        metadata = ModelMetadata(
            model_id=eff_model_id,
            model_version=eff_version,
            model_family=ModelFamily.LIGHTGBM,
            task_type=TaskType.BINARY_CLASSIFICATION,
            dataset_id=EMBER_2018_DATASET_NAME,
            dataset_version=f"{EMBER_2018_DATASET_VERSION}.v2",
            feature_schema_version=EMBER_2018_FEATURE_SCHEMA_VERSION,
            feature_count=self.feature_count,
            label_mapping={"0": "BENIGN", "1": "MALICIOUS"},
            class_order=["BENIGN", "MALICIOUS"],
            training_config=training_cfg,
            artifact_format="ONNX",
            artifact_hash=artifact_hash,
            metrics=metrics_obj,
            created_at=datetime.now(timezone.utc),
            evaluated_at=datetime.now(timezone.utc),
        )

        # 3. Atomic write of metadata JSON
        temp_meta = dest_meta.parent / f"{dest_meta.name}.tmp"
        try:
            with open(temp_meta, "w", encoding="utf-8") as mf:
                json.dump(metadata.model_dump(mode="json"), mf, indent=2)

            _safe_atomic_persist(temp_meta, dest_meta)
        except Exception as exc:
            if temp_meta.exists():
                try:
                    temp_meta.unlink()
                except OSError:
                    pass
            raise OnnxExportError(f"Failed to atomically persist ONNX metadata to {dest_meta}: {exc}") from exc

        logger.info(
            "Successfully exported ONNX model to %s (SHA-256: %s) with metadata %s",
            dest_onnx,
            artifact_hash,
            dest_meta,
        )

        return dest_onnx, dest_meta, metadata

    def export_model_file(
        self,
        model_file_path: Union[str, Path],
        output_onnx_path: Optional[Union[str, Path]] = None,
        metadata_path: Optional[Union[str, Path]] = None,
        source_metadata_path: Optional[Union[str, Path]] = None,
        operating_threshold: Optional[float] = None,
        model_id: Optional[str] = None,
        model_version: Optional[str] = None,
    ) -> Tuple[Path, Path, ModelMetadata]:
        """Load a LightGBM model from disk and export it to ONNX format.

        Args:
            model_file_path: Path to the LightGBM booster file (`.txt`).
            output_onnx_path: Destination path for the `.onnx` artifact. If omitted, uses `<stem>.onnx`.
            metadata_path: Destination path for metadata JSON.
            source_metadata_path: Optional path to existing metadata JSON. If omitted, tries `<stem>_metadata.json`.
            operating_threshold: Operating decision threshold.
            model_id: Custom model identifier.
            model_version: Custom model version string.

        Returns:
            Tuple of (onnx_path, metadata_path, ModelMetadata_instance).
        """
        src_path = Path(model_file_path).resolve()
        booster = self.load_booster(src_path)

        if output_onnx_path is None:
            eff_onnx_path = src_path.parent / f"{src_path.stem}.onnx"
        else:
            eff_onnx_path = Path(output_onnx_path).resolve()

        if source_metadata_path is None:
            candidate_meta = src_path.parent / f"{src_path.stem}_metadata.json"
            if candidate_meta.is_file():
                source_metadata_path = candidate_meta

        return self.export_booster_to_file(
            booster=booster,
            output_onnx_path=eff_onnx_path,
            metadata_path=metadata_path,
            source_metadata_path=source_metadata_path,
            operating_threshold=operating_threshold,
            model_id=model_id,
            model_version=model_version,
        )
