#!/usr/bin/env python3
"""Command-line workflow for EMBER 2018 v2 LightGBM training and evaluation.

Usage:
    python scripts/train_lightgbm.py --help
    python scripts/train_lightgbm.py --download --extract --max-train-samples 25000 --max-test-samples 10000
    python scripts/train_lightgbm.py --data-dir .data/ember --models-dir .data/models
"""

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time

# Ensure backend-api is on sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
BACKEND_DIR = REPO_ROOT / "backend-api"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import lightgbm as lgb
import numpy as np
import sklearn

from app.schemas.ml_contracts import (
    EMBER_2018_ARCHIVE_SHA256,
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
)
from app.services.ember_dataset_service import EmberDatasetService
from app.services.ember_raw_vectorizer import EmberRawFeatureVectorizer
from app.services.lightgbm_training import EvaluationReport, LightGBMTrainer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sentinel.train_lightgbm")


def parse_args() -> argparse.Namespace:
    """Parse command line options."""
    parser = argparse.ArgumentParser(
        description="Sentinel-EDR: Train and evaluate LightGBM static PE malware detector on EMBER 2018 v2."
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=".data/ember",
        help="Path to directory containing EMBER archive and JSONL shards (default: .data/ember).",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default=".data/models",
        help="Path to directory where trained models and metadata are saved (default: .data/models).",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download the official EMBER 2018 v2 archive from upstream if missing.",
    )
    parser.add_argument(
        "--extract",
        action="store_true",
        help="Safely extract the tar.bz2 archive if JSONL shards are missing.",
    )
    parser.add_argument(
        "--subset-size",
        type=int,
        default=None,
        help="Shorthand cap on number of samples per split (overridden by --max-train-samples/--max-test-samples).",
    )
    parser.add_argument(
        "--max-train-samples",
        type=int,
        default=25000,
        help="Maximum labeled samples from training partition (default: 25,000 for pilot; set 0 for unlimited).",
    )
    parser.add_argument(
        "--max-test-samples",
        type=int,
        default=10000,
        help="Maximum labeled samples from held-out test partition (default: 10,000 for pilot; set 0 for unlimited).",
    )
    parser.add_argument(
        "--stratified",
        action="store_true",
        default=True,
        help="Enforce balanced class distribution (50/50 benign/malicious) in pilot sampling (default: True).",
    )
    parser.add_argument(
        "--num-boost-round",
        type=int,
        default=100,
        help="Maximum boosting iterations (default: 100).",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.05,
        help="Boosting learning rate (default: 0.05).",
    )
    parser.add_argument(
        "--num-leaves",
        type=int,
        default=64,
        help="Max number of leaves in one tree (default: 64).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--val-ratio",
        type=float,
        default=0.2,
        help="Validation split ratio from training partition (default: 0.2).",
    )
    parser.add_argument(
        "--model-id",
        type=str,
        default="sentinel-pe-lightgbm",
        help="Model identifier (default: sentinel-pe-lightgbm).",
    )
    parser.add_argument(
        "--model-version",
        type=str,
        default="1.0.0",
        help="Semantic model version (default: 1.0.0).",
    )
    return parser.parse_args()


def main() -> int:
    """Execute training and evaluation pipeline."""
    args = parse_args()

    max_train = args.max_train_samples if args.max_train_samples > 0 else None
    max_test = args.max_test_samples if args.max_test_samples > 0 else None
    if args.subset_size is not None and args.subset_size > 0:
        max_train = args.subset_size
        max_test = args.subset_size

    is_pilot = (max_train is not None) or (max_test is not None)

    print("=" * 80)
    print(" Sentinel-EDR: LightGBM Training & Evaluation Pipeline (T014)")
    print("=" * 80)
    print(f"Python:            {sys.version.split()[0]} ({sys.platform})")
    print(f"LightGBM:          {lgb.__version__}")
    print(f"NumPy:             {np.__version__}")
    print(f"scikit-learn:      {sklearn.__version__}")
    print(f"Data dir:          {args.data_dir}")
    print(f"Models dir:        {args.models_dir}")
    print(f"Feature dim:       {EMBER_2018_CANONICAL_FEATURE_DIMENSION} ({EMBER_2018_FEATURE_SCHEMA_VERSION})")
    print(f"Execution mode:    {'Real-Data Pilot' if is_pilot else 'Full Dataset'}")
    if is_pilot:
        print(f"  Max Train:       {max_train:,} records (stratified={args.stratified})")
        print(f"  Max Test:        {max_test:,} records (stratified={args.stratified})")
    print("-" * 80)

    dataset_service = EmberDatasetService(dataset_dir=args.data_dir)

    # 1. Download if requested or needed
    if args.download or not dataset_service.archive_path.is_file():
        print("[Step 1/6] Verifying / acquiring official EMBER 2018 v2 archive...")
        if dataset_service.archive_path.is_file() and dataset_service.verify_archive_checksum():
            print(f"  Existing archive verified: {dataset_service.archive_path}")
        else:
            print(f"  Starting streaming download from {dataset_service.archive_url}...")
            last_reported = 0

            def progress_cb(current: int, total: int):
                nonlocal last_reported
                if current - last_reported >= 50 * 1024 * 1024 or current == total:
                    last_reported = current
                    pct = (current / total) * 100 if total > 0 else 0
                    print(
                        f"  Downloaded: {current / (1024*1024):.1f} / {total / (1024*1024):.1f} MB ({pct:.1f}%)",
                        flush=True,
                    )

            t0_dl = time.time()
            archive_path = dataset_service.download_archive(chunk_callback=progress_cb)
            print(f"  Archive downloaded and verified in {time.time() - t0_dl:.1f}s.")
            print(f"  Path: {archive_path}")
    else:
        print(f"[Step 1/6] Verified existing archive: {dataset_service.archive_path}")

    # 2. Extract if requested or if shards not present
    print("[Step 2/6] Inspecting / extracting archive shards...")
    t0_ext = time.time()
    dataset_service.extract_archive()
    print(f"  Extraction verified in {time.time() - t0_ext:.1f}s.")

    # 3. Discover shards & inspect
    print("[Step 3/6] Discovering shards and validating dataset...")
    try:
        train_shards, test_shard = dataset_service.discover_shards()
        print(f"  Found {len(train_shards)} training shard(s): {[s.name for s in train_shards]}")
        print(f"  Found test shard: {test_shard.name}")
    except Exception as exc:
        logger.error("Dataset shards not found: %s", exc)
        print(f"  ERROR: {exc}")
        return 1

    # 4. Vectorize to disk
    print("[Step 4/6] Streaming and vectorizing raw records to memory-mapped arrays...")
    data_path = Path(args.data_dir).resolve()
    x_train_path = data_path / "X_train.dat"
    y_train_path = data_path / "y_train.dat"
    x_test_path = data_path / "X_test.dat"
    y_test_path = data_path / "y_test.dat"

    def combined_train_generator():
        for s in train_shards:
            yield from dataset_service.stream_jsonl(s)

    train_class_counts: dict = {}
    test_class_counts: dict = {}

    t0_vec = time.time()
    n_train, excl_train = dataset_service.vectorize_records_to_memmap(
        combined_train_generator(),
        x_train_path,
        y_train_path,
        max_samples=max_train,
        stratified=args.stratified,
        class_counts_out=train_class_counts,
    )
    print(
        f"  Training partition: {n_train:,} retained samples "
        f"(Benign={train_class_counts.get(0, 0):,}, Malicious={train_class_counts.get(1, 0):,}; "
        f"excluded {excl_train:,} unlabeled)."
    )

    n_test, excl_test = dataset_service.vectorize_records_to_memmap(
        dataset_service.stream_jsonl(test_shard),
        x_test_path,
        y_test_path,
        max_samples=max_test,
        stratified=args.stratified,
        class_counts_out=test_class_counts,
    )
    print(
        f"  Held-out test partition: {n_test:,} retained samples "
        f"(Benign={test_class_counts.get(0, 0):,}, Malicious={test_class_counts.get(1, 0):,}; "
        f"excluded {excl_test:,} unlabeled). Elapsed: {time.time() - t0_vec:.1f}s."
    )

    # Load memmaps in read-only mode
    X_train, y_train = dataset_service.load_memmap_features(x_train_path, y_train_path, n_train)
    X_test, y_test = dataset_service.load_memmap_features(x_test_path, y_test_path, n_test)

    # 5. Train LightGBM model
    print("[Step 5/6] Training LightGBM model...")
    trainer = LightGBMTrainer(
        model_id=args.model_id,
        model_version=args.model_version,
        models_dir=args.models_dir,
        training_config={
            "learning_rate": args.learning_rate,
            "num_leaves": args.num_leaves,
            "seed": args.seed,
        },
    )

    t0_train = time.time()
    booster, operating_threshold, train_summary = trainer.train(
        X_train,
        y_train,
        val_ratio=args.val_ratio,
        num_boost_round=args.num_boost_round,
        random_seed=args.seed,
    )
    print(f"  Training completed in {time.time() - t0_train:.1f}s. Best iteration: {train_summary['best_iteration']}.")
    print(f"  Validation samples: {train_summary['val_sample_count']:,} (Benign={train_summary['val_negative_count']:,}, Malicious={train_summary['val_positive_count']:,}).")
    print(f"  Selected operating threshold (from validation data only): {operating_threshold:.4f}")

    # 6. Evaluate on held-out test data
    print("[Step 6/6] Evaluating on held-out test partition...")
    eval_report = trainer.evaluate(
        booster,
        X_test,
        y_test,
        operating_threshold=operating_threshold,
        split_name="test",
        is_subset_experiment=is_pilot,
        subset_sample_count=n_test if is_pilot else None,
    )

    # Persist model and metadata
    model_path, meta_path, metadata = trainer.save_model_and_metadata(
        booster,
        eval_report,
        train_summary,
    )

    # 7. Smoke test model artifact loading and inference
    print("\n[Smoke Test] Validating model artifact loading and prediction...")
    loaded_booster = lgb.Booster(model_file=str(model_path))
    test_sub = X_test[:5]
    preds = loaded_booster.predict(test_sub)
    print(f"  Loaded model successfully from: {model_path}")
    print(f"  Sample predictions (prob): {[round(p, 4) for p in preds]}")
    assert len(preds) == 5
    assert all(0.0 <= p <= 1.0 for p in preds)
    print("  Smoke test assertion passed: all predictions are valid probabilities in [0.0, 1.0].")

    print("\n" + "=" * 80)
    print(" EVALUATION RESULTS (HELD-OUT TEST SET)")
    print("=" * 80)
    print(f"Experiment type:           {'Real-Data Pilot (Subset)' if is_pilot else 'Full Dataset'}")
    print(f"Test samples evaluated:    {eval_report.sample_count:,}")
    print(f"  Benign samples (0):      {eval_report.negative_count:,}")
    print(f"  Malicious samples (1):   {eval_report.positive_count:,}")
    print(f"Operating threshold:       {eval_report.operating_threshold:.4f} (frozen from validation split)")
    print(f"ROC-AUC:                   {eval_report.roc_auc:.4f}")
    if eval_report.partial_roc_auc_low_fpr is not None:
        print(f"Low-FPR ROC-AUC (0.005):   {eval_report.partial_roc_auc_low_fpr:.4f}")
    else:
        print("Low-FPR ROC-AUC (0.005):   N/A (undefined for class sample size)")
    print(f"Accuracy:                  {eval_report.accuracy:.4f}")
    print(f"Balanced Accuracy:         {eval_report.balanced_accuracy:.4f}")
    print(f"Precision:                 {eval_report.precision:.4f}")
    print(f"Recall:                    {eval_report.recall:.4f}")
    print(f"F1 Score:                  {eval_report.f1_score:.4f}")
    print(f"False Positive Rate (FPR): {eval_report.false_positive_rate:.4f}")
    print(f"True Positive Rate (TPR):  {eval_report.true_positive_rate:.4f}")
    print(f"Confusion Matrix:          [[TN={eval_report.confusion_matrix[0][0]:,}, FP={eval_report.confusion_matrix[0][1]:,}],")
    print(f"                            [FN={eval_report.confusion_matrix[1][0]:,}, TP={eval_report.confusion_matrix[1][1]:,}]]")
    print("-" * 80)
    print(f"Model Artifact:            {model_path}")
    print(f"Model SHA-256:             {metadata.artifact_hash}")
    print(f"Metadata File:             {meta_path}")
    if eval_report.warnings:
        print("Warnings:")
        for w in eval_report.warnings:
            print(f"  - {w}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
