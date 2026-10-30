"""Tests for ONNX model export service (T015).

Verifies:
- Conversion of LightGBM binary classification models to ONNX with opset 15.
- Dynamic batch shape support for input [None, 2381] and outputs label ['None'], probabilities [None, 2].
- Atomic artifact persistence and rollback on export failure.
- SHA-256 calculation and conformance of metadata to shared JSON Schema.
- Schema validation and error handling for missing, corrupt, or mismatched models.
"""

import json
from pathlib import Path
import tempfile
import pytest
import jsonschema
import lightgbm as lgb
import numpy as np

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    ModelFamily,
    TaskType,
)
from app.services.onnx_export_service import (
    InvalidModelSchemaError,
    LightGBMModelLoadError,
    OnnxConversionError,
    OnnxExportError,
    OnnxExportValidationError,
    OnnxModelExporter,
)


@pytest.fixture
def tiny_booster():
    """Create a minimal 2,381-feature trained LightGBM booster for unit testing."""
    np.random.seed(42)
    n_samples = 40
    n_features = EMBER_2018_CANONICAL_FEATURE_DIMENSION
    X = np.random.randn(n_samples, n_features).astype(np.float32)
    y = np.array([0, 1] * (n_samples // 2), dtype=int)
    ds = lgb.Dataset(X, label=y, free_raw_data=False)
    params = {
        "objective": "binary",
        "verbose": -1,
        "learning_rate": 0.1,
        "num_leaves": 8,
        "seed": 42,
    }
    booster = lgb.train(params, ds, num_boost_round=3)
    return booster


@pytest.fixture
def schema_validator():
    """Load the shared model metadata JSON Schema."""
    schema_path = Path("shared/schemas/model_metadata.schema.json")
    if not schema_path.is_file():
        pytest.skip(f"Schema file not found at {schema_path}")
    with open(schema_path, "r", encoding="utf-8") as sf:
        schema = json.load(sf)
    return lambda data: jsonschema.validate(data, schema)


class TestOnnxExportService:
    """Test suite for OnnxModelExporter."""

    def test_exporter_initialization_defaults(self):
        """Exporter initializes with canonical 2,381 features and target opset 15."""
        exporter = OnnxModelExporter()
        assert exporter.feature_count == EMBER_2018_CANONICAL_FEATURE_DIMENSION
        assert exporter.target_opset == 15
        assert exporter.input_name == "features"

    def test_convert_booster_to_onnx_proto(self, tiny_booster):
        """Converting a booster returns a valid onnx.ModelProto with expected tensor dimensions."""
        exporter = OnnxModelExporter()
        model_proto = exporter.convert_booster_to_onnx(tiny_booster, name="test_model")
        assert model_proto is not None
        assert model_proto.graph.name == "test_model"

        # Verify input tensor definition
        assert len(model_proto.graph.input) == 1
        inp = model_proto.graph.input[0]
        assert inp.name == "features"
        shape_dims = inp.type.tensor_type.shape.dim
        assert len(shape_dims) == 2
        assert shape_dims[1].dim_value == EMBER_2018_CANONICAL_FEATURE_DIMENSION

        # Verify outputs: label and probabilities
        output_names = [out.name for out in model_proto.graph.output]
        assert "label" in output_names
        assert "probabilities" in output_names

        # Verify dynamic batch dimension parameter on label output
        label_out = next(o for o in model_proto.graph.output if o.name == "label")
        assert label_out.type.tensor_type.shape.dim[0].dim_param == "None"

    def test_export_booster_to_file_and_schema_validation(self, tiny_booster, schema_validator, tmp_path):
        """Exporting a booster to disk creates valid .onnx and conforming metadata files."""
        exporter = OnnxModelExporter()
        onnx_file = tmp_path / "tiny_test.onnx"
        meta_file = tmp_path / "tiny_test_metadata.json"

        out_onnx, out_meta, meta_obj = exporter.export_booster_to_file(
            booster=tiny_booster,
            output_onnx_path=onnx_file,
            metadata_path=meta_file,
            operating_threshold=0.8856,
            model_id="tiny-test-model",
            model_version="1.0.0",
        )

        assert out_onnx.is_file()
        assert out_meta.is_file()
        assert out_onnx.stat().st_size > 0
        assert meta_obj.artifact_format == "ONNX"
        assert len(meta_obj.artifact_hash) == 64
        assert meta_obj.training_config["operating_threshold"] == 0.8856

        # Validate against shared JSON Schema
        with open(out_meta, "r", encoding="utf-8") as mf:
            meta_json = json.load(mf)
        schema_validator(meta_json)

    def test_atomic_persistence_preserves_existing_on_failure(self, tiny_booster, tmp_path, monkeypatch):
        """If serialization or write fails during export, existing target files are not corrupted."""
        exporter = OnnxModelExporter()
        target_onnx = tmp_path / "preserve_test.onnx"
        target_onnx.write_text("existing_valid_content")

        # Simulate conversion failure
        def mock_convert(*args, **kwargs):
            raise RuntimeError("Simulated converter crash")

        monkeypatch.setattr("app.services.onnx_export_service.convert_lightgbm", mock_convert)

        with pytest.raises(OnnxConversionError, match="Simulated converter crash"):
            exporter.export_booster_to_file(
                booster=tiny_booster,
                output_onnx_path=target_onnx,
            )

        # Existing file must remain intact
        assert target_onnx.read_text() == "existing_valid_content"

    def test_load_nonexistent_model_raises_load_error(self, tmp_path):
        """Attempting to load a nonexistent model path raises LightGBMModelLoadError."""
        exporter = OnnxModelExporter()
        non_existent = tmp_path / "does_not_exist.txt"
        with pytest.raises(LightGBMModelLoadError, match="does not exist"):
            exporter.load_booster(non_existent)

    def test_mismatched_feature_dimension_rejected(self, tmp_path):
        """A model with wrong feature count is rejected by InvalidModelSchemaError."""
        np.random.seed(42)
        X = np.random.randn(20, 10).astype(np.float32)
        y = np.array([0, 1] * 10)
        ds = lgb.Dataset(X, y)
        small_booster = lgb.train({"objective": "binary", "verbose": -1}, ds, num_boost_round=1)

        model_path = tmp_path / "small_model.txt"
        small_booster.save_model(str(model_path))

        exporter = OnnxModelExporter(feature_count=EMBER_2018_CANONICAL_FEATURE_DIMENSION)
        with pytest.raises(InvalidModelSchemaError, match="does not match expected feature schema dimension"):
            exporter.load_booster(model_path)

    def test_real_model_a_export_integrity(self, schema_validator):
        """Verify the exported Design A ONNX artifact matches its metadata and schema."""
        onnx_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx")
        meta_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2_onnx_metadata.json")

        if not onnx_path.is_file() or not meta_path.is_file():
            pytest.skip("Design A ONNX artifacts not present on disk.")

        assert onnx_path.stat().st_size > 0

        with open(meta_path, "r", encoding="utf-8") as mf:
            meta_json = json.load(mf)

        schema_validator(meta_json)
        assert meta_json["model_family"] == "lightgbm"
        assert meta_json["task_type"] == "binary_classification"
        assert meta_json["artifact_format"] == "ONNX"
        assert meta_json["feature_count"] == EMBER_2018_CANONICAL_FEATURE_DIMENSION

    def test_real_model_b_export_integrity(self, schema_validator):
        """Verify the exported Design B ONNX artifact matches its metadata and schema."""
        onnx_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.onnx")
        meta_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal_onnx_metadata.json")

        if not onnx_path.is_file() or not meta_path.is_file():
            pytest.skip("Design B ONNX artifacts not present on disk.")

        assert onnx_path.stat().st_size > 0

        with open(meta_path, "r", encoding="utf-8") as mf:
            meta_json = json.load(mf)

        schema_validator(meta_json)
        assert meta_json["artifact_format"] == "ONNX"
        assert meta_json["feature_count"] == EMBER_2018_CANONICAL_FEATURE_DIMENSION
