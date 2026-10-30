"""LightGBM training, validation, and evaluation service for Sentinel-EDR.

Implements:
- Binary malware classification model training using the approved 'lightgbm' engine.
- Strict label policy enforcement (0=BENIGN, 1=MALICIOUS, -1 excluded).
- Official test partition isolation: test set is held-out and never used for tuning or early stopping.
- Operating threshold determination on validation split only.
- Comprehensive evaluation metrics: ROC-AUC, low-FPR partial ROC-AUC (max_fpr=0.005),
  Precision, Recall, F1, Balanced Accuracy, and Confusion Matrix.
- Atomic model artifact and ModelMetadata persistence conforming to T012 contracts.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

import lightgbm as lgb
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_DATASET_NAME,
    EMBER_2018_DATASET_VERSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
    EMBER_2018_FEATURE_VERSION,
    ModelFamily,
    ModelMetadata,
    ModelMetrics,
    TaskType,
)

logger = logging.getLogger("sentinel.services.lightgbm_training")


DEFAULT_LIGHTGBM_PARAMS: Dict[str, Any] = {
    "objective": "binary",
    "metric": ["binary_logloss", "auc"],
    "boosting_type": "gbdt",
    "learning_rate": 0.05,
    "num_leaves": 64,
    "max_depth": -1,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "seed": 42,
    "deterministic": True,
    "verbose": -1,
    "n_jobs": -1,
}


class ModelTrainingError(Exception):
    """Base exception for model training and evaluation errors."""


class InsufficientClassDataError(ModelTrainingError):
    """Raised when training data does not contain both binary target classes."""


class EvaluationMetricError(ModelTrainingError):
    """Raised when evaluation cannot be computed due to invalid data."""


@dataclass
class EvaluationReport:
    """Detailed evaluation report computed on a held-out evaluation split."""

    sample_count: int
    positive_count: int
    negative_count: int
    roc_auc: float
    partial_roc_auc_low_fpr: Optional[float]
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    balanced_accuracy: float
    false_positive_rate: float
    true_positive_rate: float
    confusion_matrix: List[List[int]]
    operating_threshold: float
    evaluation_split: str = "test"
    is_subset_experiment: bool = False
    subset_sample_count: Optional[int] = None
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to serializable dictionary."""
        return {
            "sample_count": self.sample_count,
            "positive_count": self.positive_count,
            "negative_count": self.negative_count,
            "roc_auc": self.roc_auc,
            "partial_roc_auc_low_fpr": self.partial_roc_auc_low_fpr,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "accuracy": self.accuracy,
            "balanced_accuracy": self.balanced_accuracy,
            "false_positive_rate": self.false_positive_rate,
            "true_positive_rate": self.true_positive_rate,
            "confusion_matrix": self.confusion_matrix,
            "operating_threshold": self.operating_threshold,
            "evaluation_split": self.evaluation_split,
            "is_subset_experiment": self.is_subset_experiment,
            "subset_sample_count": self.subset_sample_count,
            "warnings": list(self.warnings),
        }


class LightGBMTrainer:
    """Manages training, validation, threshold selection, and evaluation for LightGBM models."""

    def __init__(
        self,
        *,
        model_id: str = "sentinel-pe-lightgbm",
        model_version: str = "1.0.0",
        training_config: Optional[Dict[str, Any]] = None,
        models_dir: Union[str, Path] = ".data/models",
    ) -> None:
        self.model_id = model_id
        self.model_version = model_version
        self.models_dir = Path(models_dir).resolve()
        self.config = dict(DEFAULT_LIGHTGBM_PARAMS)
        if training_config:
            self.config.update(training_config)

    # --------------------------------------------------------------------------
    # 1. Training & Validation
    # --------------------------------------------------------------------------
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        *,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        val_ratio: float = 0.2,
        num_boost_round: int = 100,
        early_stopping_rounds: int = 20,
        random_seed: int = 42,
    ) -> Tuple[lgb.Booster, float, Dict[str, Any]]:
        """Train a LightGBM binary classifier and determine operating threshold on validation data.

        Args:
            X_train: Training features array of shape (N, 2381).
            y_train: Training labels array (0 or 1).
            X_val: Optional held-out validation features.
            y_val: Optional held-out validation labels.
            val_ratio: Split ratio if X_val is not supplied.
            num_boost_round: Maximum boosting iterations.
            early_stopping_rounds: Early stopping patience.
            random_seed: Seed for reproducibility.

        Returns:
            Tuple of (trained_booster, operating_threshold, training_summary_dict).
        """
        # Validate dimensions
        if X_train.ndim != 2 or X_train.shape[1] != EMBER_2018_CANONICAL_FEATURE_DIMENSION:
            raise ModelTrainingError(
                f"Expected features with shape (N, {EMBER_2018_CANONICAL_FEATURE_DIMENSION}), got {X_train.shape}"
            )

        if len(X_train) != len(y_train):
            raise ModelTrainingError(f"Features length ({len(X_train)}) != labels length ({len(y_train)})")

        # Verify finite numbers
        if not np.all(np.isfinite(X_train)):
            raise ModelTrainingError("Training features contain non-finite values (NaN or Inf).")

        # Enforce binary class distribution
        unique_classes = set(np.unique(y_train))
        if unique_classes - {0.0, 1.0, 0, 1}:
            raise ModelTrainingError(f"Unexpected target classes in training data: {unique_classes}")

        if len(unique_classes) < 2:
            raise InsufficientClassDataError(
                f"Training data contains only one class ({unique_classes}). "
                "Binary classification requires both benign (0) and malicious (1) samples."
            )

        # Prepare train and validation sets
        if X_val is None or y_val is None:
            X_tr, X_va, y_tr, y_va = train_test_split(
                X_train,
                y_train,
                test_size=val_ratio,
                random_state=random_seed,
                stratify=y_train if len(unique_classes) > 1 else None,
            )
        else:
            X_tr, y_tr = X_train, y_train
            X_va, y_va = X_val, y_val

        logger.info(
            "Training LightGBM model with %d train samples and %d validation samples.",
            len(X_tr),
            len(X_va),
        )

        train_data = lgb.Dataset(X_tr, label=y_tr)
        val_data = lgb.Dataset(X_va, label=y_va, reference=train_data)

        # Configure hyperparameters
        train_params = dict(self.config)
        train_params["seed"] = random_seed

        callbacks = [
            lgb.early_stopping(stopping_rounds=early_stopping_rounds, verbose=False),
            lgb.log_evaluation(period=0),  # silent
        ]

        booster = lgb.train(
            train_params,
            train_data,
            num_boost_round=num_boost_round,
            valid_sets=[train_data, val_data],
            valid_names=["train", "valid"],
            callbacks=callbacks,
        )

        # Determine operating threshold strictly on validation split
        val_preds = booster.predict(X_va)
        operating_threshold = self._select_operating_threshold(y_va, val_preds)

        training_summary = {
            "best_iteration": booster.best_iteration,
            "train_sample_count": len(X_tr),
            "val_sample_count": len(X_va),
            "train_positive_count": int(np.sum(y_tr == 1)),
            "train_negative_count": int(np.sum(y_tr == 0)),
            "val_positive_count": int(np.sum(y_va == 1)),
            "val_negative_count": int(np.sum(y_va == 0)),
            "operating_threshold": operating_threshold,
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }

        return booster, operating_threshold, training_summary

    @staticmethod
    def _select_operating_threshold(
        y_true: np.ndarray,
        y_prob: np.ndarray,
        *,
        target_max_fpr: float = 0.005,
    ) -> float:
        """Select operating threshold on validation data targeting low false positive rate (<= 0.005).

        If target_max_fpr cannot be satisfied, selects threshold that maximizes F1 score.
        """
        # Test candidate thresholds from 0.1 to 0.99
        thresholds = np.linspace(0.1, 0.99, 90)
        best_threshold = 0.5
        best_f1 = -1.0

        low_fpr_candidates = []

        for th in thresholds:
            pred_binary = (y_prob >= th).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_true, pred_binary, labels=[0, 1]).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            score_f1 = f1_score(y_true, pred_binary, zero_division=0)

            if fpr <= target_max_fpr:
                low_fpr_candidates.append((th, score_f1, fpr))

            if score_f1 > best_f1:
                best_f1 = score_f1
                best_threshold = float(th)

        # If any threshold meets the target low FPR, pick the one with highest F1 among them
        if low_fpr_candidates:
            low_fpr_candidates.sort(key=lambda item: item[1], reverse=True)
            return float(low_fpr_candidates[0][0])

        return best_threshold

    # --------------------------------------------------------------------------
    # 2. Held-Out Evaluation
    # --------------------------------------------------------------------------
    def evaluate(
        self,
        booster: lgb.Booster,
        X_test: np.ndarray,
        y_test: np.ndarray,
        *,
        operating_threshold: float = 0.5,
        split_name: str = "test",
        is_subset_experiment: bool = False,
        subset_sample_count: Optional[int] = None,
    ) -> EvaluationReport:
        """Evaluate trained model on held-out test data using the frozen operating threshold."""
        warnings: List[str] = []

        if len(X_test) != len(y_test):
            raise ModelTrainingError(f"X_test length ({len(X_test)}) != y_test length ({len(y_test)})")

        if len(X_test) == 0:
            raise ModelTrainingError("Test dataset is empty.")

        n_samples = len(y_test)
        pos_count = int(np.sum(y_test == 1))
        neg_count = int(np.sum(y_test == 0))

        if pos_count == 0 or neg_count == 0:
            warnings.append(
                f"Test dataset contains only one class (pos={pos_count}, neg={neg_count}). "
                "ROC-AUC and other discrimination metrics cannot be computed."
            )

        y_prob = booster.predict(X_test)
        y_pred = (y_prob >= operating_threshold).astype(int)

        # ROC-AUC
        if pos_count > 0 and neg_count > 0:
            roc_auc = float(roc_auc_score(y_test, y_prob))
            # Low FPR ROC-AUC (max_fpr=0.005)
            try:
                partial_auc = float(roc_auc_score(y_test, y_prob, max_fpr=0.005))
            except Exception as exc:
                partial_auc = None
                warnings.append(f"Could not compute low-FPR ROC-AUC (max_fpr=0.005): {exc}")
        else:
            roc_auc = 0.0
            partial_auc = None

        # Standard classification metrics
        precision = float(precision_score(y_test, y_pred, zero_division=0))
        recall = float(recall_score(y_test, y_pred, zero_division=0))
        score_f1 = float(f1_score(y_test, y_pred, zero_division=0))
        accuracy = float(accuracy_score(y_test, y_pred))
        bal_acc = float(balanced_accuracy_score(y_test, y_pred))

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        tpr = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0

        if is_subset_experiment:
            warnings.append(
                f"Evaluation conducted on a subset experiment ({subset_sample_count or n_samples} samples). "
                "Results must not be compared directly with full EMBER benchmark scores."
            )

        return EvaluationReport(
            sample_count=n_samples,
            positive_count=pos_count,
            negative_count=neg_count,
            roc_auc=roc_auc,
            partial_roc_auc_low_fpr=partial_auc,
            precision=precision,
            recall=recall,
            f1_score=score_f1,
            accuracy=accuracy,
            balanced_accuracy=bal_acc,
            false_positive_rate=fpr,
            true_positive_rate=tpr,
            confusion_matrix=cm.tolist(),
            operating_threshold=operating_threshold,
            evaluation_split=split_name,
            is_subset_experiment=is_subset_experiment,
            subset_sample_count=subset_sample_count,
            warnings=warnings,
        )

    # --------------------------------------------------------------------------
    # 3. Model & Metadata Persistence
    # --------------------------------------------------------------------------
    def save_model_and_metadata(
        self,
        booster: lgb.Booster,
        eval_report: EvaluationReport,
        training_summary: Dict[str, Any],
        *,
        model_filename: Optional[str] = None,
        metadata_filename: Optional[str] = None,
    ) -> Tuple[Path, Path, ModelMetadata]:
        """Atomically persist the native LightGBM model and its validated ModelMetadata.

        Args:
            booster: Trained LightGBM booster.
            eval_report: Evaluation report computed on held-out split.
            training_summary: Training summary details.
            model_filename: Custom filename for model text artifact.
            metadata_filename: Custom filename for metadata JSON.

        Returns:
            Tuple of (model_file_path, metadata_file_path, ModelMetadata_instance).
        """
        self.models_dir.mkdir(parents=True, exist_ok=True)

        m_name = model_filename or f"{self.model_id}.txt"
        meta_name = metadata_filename or f"{self.model_id}_metadata.json"

        final_model_path = self.models_dir / m_name
        final_meta_path = self.models_dir / meta_name

        # 1. Save model text artifact to temporary file
        temp_model = self.models_dir / f"{m_name}.tmp"
        booster.save_model(str(temp_model))

        # 2. Compute canonical SHA-256 digest of saved model file
        hasher = hashlib.sha256()
        with open(temp_model, "rb") as fin:
            for chunk in iter(lambda: fin.read(65536), b""):
                hasher.update(chunk)
        artifact_hash = hasher.hexdigest().lower()

        # Atomic rename of model file
        if temp_model.exists():
            if final_model_path.exists():
                final_model_path.unlink()
            temp_model.replace(final_model_path)

        # 3. Assemble validated ModelMetadata conforming to T012 schema
        metrics = ModelMetrics(
            roc_auc=eval_report.roc_auc,
            precision=eval_report.precision,
            recall=eval_report.recall,
            f1_score=eval_report.f1_score,
            false_positive_rate=eval_report.false_positive_rate,
            evaluation_split=eval_report.evaluation_split,
        )

        metadata = ModelMetadata(
            model_id=self.model_id,
            model_version=self.model_version,
            model_family=ModelFamily.LIGHTGBM,
            task_type=TaskType.BINARY_CLASSIFICATION,
            dataset_id=EMBER_2018_DATASET_NAME,
            dataset_version=f"{EMBER_2018_DATASET_VERSION}.v{EMBER_2018_FEATURE_VERSION}",
            feature_schema_version=EMBER_2018_FEATURE_SCHEMA_VERSION,
            feature_count=EMBER_2018_CANONICAL_FEATURE_DIMENSION,
            label_mapping={"0": "BENIGN", "1": "MALICIOUS"},
            class_order=["BENIGN", "MALICIOUS"],
            training_config={
                **self.config,
                **training_summary,
                "is_subset_experiment": eval_report.is_subset_experiment,
                "subset_sample_count": eval_report.subset_sample_count,
            },
            artifact_format="LightGBM_Text",
            artifact_hash=artifact_hash,
            metrics=metrics,
            created_at=datetime.now(timezone.utc),
            evaluated_at=datetime.now(timezone.utc),
        )

        # 4. Atomic write of metadata JSON
        temp_meta = self.models_dir / f"{meta_name}.tmp"
        with open(temp_meta, "w", encoding="utf-8") as fout:
            json.dump(metadata.model_dump(mode="json"), fout, indent=2)

        if temp_meta.exists():
            if final_meta_path.exists():
                final_meta_path.unlink()
            temp_meta.replace(final_meta_path)

        logger.info(
            "Saved model artifact (%s) with SHA-256 %s and metadata (%s)",
            final_model_path,
            artifact_hash,
            final_meta_path,
        )

        return final_model_path, final_meta_path, metadata
