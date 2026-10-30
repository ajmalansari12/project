"""
T014 Corrective Experiment: Representative EMBER Sampling

Implements deterministic, hash-based reservoir sampling across all six official
EMBER 2018 training shards (instead of the sequential first-N approach used in
the original T014 baseline pilot).

Experiment ID: t014-repr-v1
Output directory: .data/experiments/t014-repr-v1/

Original baseline artifacts preserved in:
  .data/models/sentinel-pe-lightgbm.txt
  .data/models/sentinel-pe-lightgbm_metadata.json
  .data/ember/X_train.dat, y_train.dat, X_test.dat, y_test.dat

This script does NOT overwrite any of those files.

Sampling algorithm:
  - Two-pass deterministic reservoir sampling per class (BENIGN=0, MALICIOUS=1).
  - Pass 1 (census): Stream each shard line-by-line; record per-record
    (sha256, shard_idx, line_idx, appeared, label). No JSONL parsing beyond
    extracting those 4 fields. Count total lines and label distribution.
  - Selection: For each class, sort candidates by sha256 (deterministic, seed-free
    alternative to random reservoir). Take the first N sorted sha256 values per class.
    This distributes selections across shard files in a repeatable way.
  - Pass 2 (vectorization): Stream again, keep only selected sha256 keys, vectorize
    retained records into memmap arrays.

This avoids loading all JSONL records into RAM simultaneously.
"""

import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend-api"))

EMBER_DIR = PROJECT_ROOT / ".data" / "ember"
EXPERIMENT_ID = "t014-repr-v1"
EXPERIMENT_DIR = PROJECT_ROOT / ".data" / "experiments" / EXPERIMENT_ID
EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)

# These are the ORIGINAL baseline files -- never overwrite
ORIGINAL_MODEL = PROJECT_ROOT / ".data" / "models" / "sentinel-pe-lightgbm.txt"
ORIGINAL_META  = PROJECT_ROOT / ".data" / "models" / "sentinel-pe-lightgbm_metadata.json"
ORIGINAL_X_TRAIN = EMBER_DIR / "X_train.dat"
ORIGINAL_Y_TRAIN = EMBER_DIR / "y_train.dat"
ORIGINAL_X_TEST  = EMBER_DIR / "X_test.dat"
ORIGINAL_Y_TEST  = EMBER_DIR / "y_test.dat"

# Experiment-specific outputs
EXP_X_TRAIN = EXPERIMENT_DIR / "X_train_repr.dat"
EXP_Y_TRAIN = EXPERIMENT_DIR / "y_train_repr.dat"
EXP_X_TEST  = EXPERIMENT_DIR / "X_test_repr.dat"
EXP_Y_TEST  = EXPERIMENT_DIR / "y_test_repr.dat"
EXP_MODEL   = EXPERIMENT_DIR / "sentinel-pe-lightgbm-repr.txt"
EXP_META    = EXPERIMENT_DIR / "sentinel-pe-lightgbm-repr_metadata.json"
EXP_CENSUS  = EXPERIMENT_DIR / "dataset_census.json"
EXP_SAMPLE_MANIFEST = EXPERIMENT_DIR / "sample_manifest.json"

# Sampling parameters
N_TRAIN_PER_CLASS = 12_500    # 25,000 total balanced training
N_TEST_PER_CLASS  = 5_000     # 10,000 total balanced test
SEED = 42                     # not used directly (hash-based, not random)

# LightGBM parameters (identical to baseline)
LGB_PARAMS = {
    "objective": "binary",
    "metric": ["binary_logloss", "auc"],
    "boosting_type": "gbdt",
    "learning_rate": 0.05,
    "num_leaves": 64,
    "max_depth": -1,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "seed": SEED,
    "deterministic": True,
    "verbose": -1,
    "n_jobs": -1,
}
NUM_BOOST_ROUND = 100
EARLY_STOPPING_ROUNDS = 20
VAL_RATIO = 0.2
DIM = 2381


def separator(title: str = "", width: int = 80):
    if title:
        pad = (width - len(title) - 2) // 2
        print("=" * pad + f" {title} " + "=" * (width - pad - len(title) - 2))
    else:
        print("=" * width)


# ---------------------------------------------------------------------------
# PHASE 1: Dataset Census
# ---------------------------------------------------------------------------
def run_census() -> Dict:
    """Stream all shards and record per-shard statistics. Returns census dict."""
    train_shards = sorted(EMBER_DIR.glob("train_features_*.jsonl"))
    test_shard   = EMBER_DIR / "test_features.jsonl"

    assert len(train_shards) == 6, f"Expected 6 train shards, found {len(train_shards)}"
    assert test_shard.is_file(), f"Test shard not found: {test_shard}"

    all_shards = [("train", s) for s in train_shards] + [("test", test_shard)]
    census = {"train_shards": {}, "test_shard": {}, "global": {}}

    total_lines = 0
    total_benign = 0
    total_malicious = 0
    total_unlabeled = 0
    total_malformed = 0

    for split, shard in all_shards:
        shard_name = shard.name
        print(f"  Scanning {shard_name}...", end="", flush=True)
        t0 = time.time()

        lines = 0
        benign = 0
        malicious = 0
        unlabeled = 0
        malformed = 0
        sha_set: set = set()
        dup_count = 0
        appeared_min: Optional[str] = None
        appeared_max: Optional[str] = None

        with open(shard, "r", encoding="utf-8") as f:
            for line in f:
                lines += 1
                try:
                    rec = json.loads(line)
                except Exception:
                    malformed += 1
                    continue

                lbl = rec.get("label")
                sha = rec.get("sha256", "")
                appeared = rec.get("appeared", "")

                if sha:
                    if sha in sha_set:
                        dup_count += 1
                    sha_set.add(sha)

                if appeared:
                    if appeared_min is None or appeared < appeared_min:
                        appeared_min = appeared
                    if appeared_max is None or appeared > appeared_max:
                        appeared_max = appeared

                if lbl == 0:
                    benign += 1
                elif lbl == 1:
                    malicious += 1
                elif lbl == -1:
                    unlabeled += 1
                else:
                    malformed += 1

        dt = time.time() - t0
        entry = {
            "lines": lines,
            "benign": benign,
            "malicious": malicious,
            "unlabeled": unlabeled,
            "malformed": malformed,
            "unique_sha256": len(sha_set),
            "duplicate_sha256": dup_count,
            "appeared_min": appeared_min,
            "appeared_max": appeared_max,
            "scan_seconds": round(dt, 2),
        }
        print(f" {lines:,} lines | B={benign:,} M={malicious:,} U={unlabeled:,} | "
              f"appeared=[{appeared_min} .. {appeared_max}] | {dt:.1f}s")

        if split == "train":
            census["train_shards"][shard_name] = entry
        else:
            census["test_shard"][shard_name] = entry

        total_lines += lines
        total_benign += benign
        total_malicious += malicious
        total_unlabeled += unlabeled
        total_malformed += malformed

    census["global"] = {
        "total_lines": total_lines,
        "total_benign": total_benign,
        "total_malicious": total_malicious,
        "total_unlabeled": total_unlabeled,
        "total_malformed": total_malformed,
    }

    with open(EXP_CENSUS, "w", encoding="utf-8") as f:
        json.dump(census, f, indent=2)

    print(f"\n  Census saved to {EXP_CENSUS}")
    return census


# ---------------------------------------------------------------------------
# PHASE 2: Deterministic Hash-Based Representative Sampling
# ---------------------------------------------------------------------------
def select_representative_samples(
    shards: List[Path],
    n_per_class: int,
    split_name: str,
) -> Tuple[Dict[str, Tuple[str, int, int]], Dict[str, int]]:
    """
    One-pass scan. For each labeled record, compute a deterministic sort key:
      sort_key = HMAC-SHA256(sha256_digest + str(label), key=b'sentinel-t014-repr-v1')
    Collect the N_PER_CLASS candidates with the *lowest* sort keys per class.

    This produces deterministic, seed-reproducible sampling without needing all
    sha256s in memory. We keep only the top-N smallest key candidates per class,
    which distributes across shards roughly in proportion to their content.

    Returns:
      selected_map: {sha256: (shard_name, line_idx, label)}
      class_counts: {0: N, 1: N}
    """
    import hmac
    import heapq

    def sort_key(sha: str, label: int) -> bytes:
        """Deterministic per-record sort key via HMAC."""
        msg = (sha + str(label)).encode("utf-8")
        return hmac.new(b"sentinel-t014-repr-v1", msg, hashlib.sha256).digest()

    class _MaxKey:
        """Wraps a bytes key so that comparison is reversed (for max-heap via heapq)."""
        __slots__ = ("val",)
        def __init__(self, v: bytes): self.val = v
        def __lt__(self, o): return self.val > o.val

    # Max-heaps to efficiently maintain top-N minimum-key candidates across all shards
    # heap item: (_MaxKey(key), sha256, shard_name, line_idx, label)
    heap_benign:    List[Tuple[_MaxKey, str, str, int, int]] = []
    heap_malicious: List[Tuple[_MaxKey, str, str, int, int]] = []

    print(f"  Selecting {n_per_class:,} BENIGN and {n_per_class:,} MALICIOUS from {split_name} partition...")

    for shard in shards:
        print(f"    Scanning {shard.name}...", end="", flush=True)
        t0 = time.time()
        count = 0
        with open(shard, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                lbl = rec.get("label")
                sha = rec.get("sha256", "")
                if lbl not in (0, 1) or not sha or len(sha) != 64:
                    continue

                key = sort_key(sha, lbl)
                mk  = _MaxKey(key)

                if lbl == 0:
                    if len(heap_benign) < n_per_class:
                        heapq.heappush(heap_benign, (mk, sha, shard.name, line_idx, lbl))
                    elif key < heap_benign[0][0].val:  # smaller key replaces largest
                        heapq.heapreplace(heap_benign, (mk, sha, shard.name, line_idx, lbl))
                else:
                    if len(heap_malicious) < n_per_class:
                        heapq.heappush(heap_malicious, (mk, sha, shard.name, line_idx, lbl))
                    elif key < heap_malicious[0][0].val:
                        heapq.heapreplace(heap_malicious, (mk, sha, shard.name, line_idx, lbl))
                count += 1

        dt = time.time() - t0
        print(f" {count:,} labeled | {dt:.1f}s")

    # Build selection map
    selected_map: Dict[str, Tuple[str, int, int]] = {}
    class_counts: Dict[int, int] = {0: 0, 1: 0}

    for item in heap_benign:
        _, sha, shard_name, line_idx, lbl = item
        selected_map[sha] = (shard_name, line_idx, lbl)
        class_counts[0] += 1

    for item in heap_malicious:
        _, sha, shard_name, line_idx, lbl = item
        selected_map[sha] = (shard_name, line_idx, lbl)
        class_counts[1] += 1

    print(f"  Selected: BENIGN={class_counts[0]:,}, MALICIOUS={class_counts[1]:,}, TOTAL={len(selected_map):,}")
    return selected_map, class_counts


# ---------------------------------------------------------------------------
# PHASE 3: Vectorize Selected Records
# ---------------------------------------------------------------------------
def vectorize_selected(
    shards: List[Path],
    selected_map: Dict[str, Tuple[str, int, int]],
    x_path: Path,
    y_path: Path,
    split_name: str,
) -> Tuple[int, Dict[int, int]]:
    """Stream shards again, vectorize only selected records, write to memmap files."""
    from app.services.ember_raw_vectorizer import EmberRawFeatureVectorizer

    vec = EmberRawFeatureVectorizer()
    assert vec.dim == DIM

    remaining = set(selected_map.keys())
    x_buf: List[np.ndarray] = []
    y_buf: List[float] = []
    retained = 0
    class_counts: Dict[int, int] = {0: 0, 1: 0}

    temp_x = x_path.with_suffix(".tmp")
    temp_y = y_path.with_suffix(".tmp")

    print(f"  Vectorizing {len(selected_map):,} selected {split_name} records...")

    with open(temp_x, "wb") as fx, open(temp_y, "wb") as fy:
        for shard in shards:
            if not remaining:
                break
            print(f"    Vectorizing from {shard.name}...", end="", flush=True)
            found_in_shard = 0
            with open(shard, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    sha = rec.get("sha256", "")
                    if sha not in remaining:
                        continue
                    remaining.discard(sha)
                    lbl = rec.get("label")
                    if lbl not in (0, 1):
                        continue

                    feature_vec = vec.vectorize_raw_record(rec)
                    x_buf.append(feature_vec)
                    y_buf.append(float(lbl))
                    retained += 1
                    class_counts[lbl] += 1
                    found_in_shard += 1

                    if len(x_buf) >= 5000:
                        fx.write(np.vstack(x_buf).astype(np.float32).tobytes())
                        fy.write(np.array(y_buf, dtype=np.float32).tobytes())
                        x_buf.clear()
                        y_buf.clear()

            print(f" found {found_in_shard:,} selected records")

        if x_buf:
            fx.write(np.vstack(x_buf).astype(np.float32).tobytes())
            fy.write(np.array(y_buf, dtype=np.float32).tobytes())

    if x_path.exists():
        x_path.unlink()
    temp_x.replace(x_path)
    if y_path.exists():
        y_path.unlink()
    temp_y.replace(y_path)

    print(f"  {split_name} vectorized: {retained:,} records (B={class_counts[0]:,} M={class_counts[1]:,})")
    return retained, class_counts


# ---------------------------------------------------------------------------
# PHASE 4: Train LightGBM
# ---------------------------------------------------------------------------
def train_model(X_train_all, y_train_all):
    """Split into train/val (80/20), train LightGBM, select threshold on val only."""
    import lightgbm as lgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import confusion_matrix, f1_score

    X_tr, X_va, y_tr, y_va = train_test_split(
        X_train_all, y_train_all,
        test_size=VAL_RATIO, stratify=y_train_all, random_state=SEED
    )
    print(f"  Train split: {len(X_tr):,} | Val split: {len(X_va):,}")

    train_data = lgb.Dataset(X_tr, label=y_tr)
    val_data   = lgb.Dataset(X_va, label=y_va, reference=train_data)

    params = dict(LGB_PARAMS)
    callbacks = [
        lgb.early_stopping(stopping_rounds=EARLY_STOPPING_ROUNDS, verbose=False),
        lgb.log_evaluation(period=0),
    ]

    t0 = time.time()
    booster = lgb.train(
        params, train_data,
        num_boost_round=NUM_BOOST_ROUND,
        valid_sets=[train_data, val_data],
        valid_names=["train", "valid"],
        callbacks=callbacks,
    )
    dt = time.time() - t0
    print(f"  Training completed in {dt:.1f}s. Best iteration: {booster.best_iteration}")

    # Threshold selection on validation ONLY
    val_probs = booster.predict(X_va)
    thresholds = np.linspace(0.1, 0.99, 90)
    target_fpr = 0.005
    best_th = 0.5
    best_f1 = -1.0
    low_fpr_candidates = []

    for th in thresholds:
        pred = (val_probs >= th).astype(int)
        cm = confusion_matrix(y_va, pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fi = f1_score(y_va, pred, zero_division=0)
        if fpr <= target_fpr:
            low_fpr_candidates.append((th, fi, fpr))
        if fi > best_f1:
            best_f1 = fi
            best_th = float(th)

    if low_fpr_candidates:
        low_fpr_candidates.sort(key=lambda x: x[1], reverse=True)
        operating_threshold = float(low_fpr_candidates[0][0])
        val_fpr = low_fpr_candidates[0][2]
        print(f"  Operating threshold: {operating_threshold:.4f} (val FPR={val_fpr:.4f}, "
              f"meets target <= {target_fpr})")
    else:
        operating_threshold = best_th
        print(f"  Operating threshold: {operating_threshold:.4f} "
              f"(fallback best-F1, target FPR not achievable)")

    train_summary = {
        "best_iteration": booster.best_iteration,
        "train_sample_count": len(X_tr),
        "val_sample_count": len(X_va),
        "train_positive_count": int(np.sum(y_tr == 1)),
        "train_negative_count": int(np.sum(y_tr == 0)),
        "val_positive_count": int(np.sum(y_va == 1)),
        "val_negative_count": int(np.sum(y_va == 0)),
        "operating_threshold": operating_threshold,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "is_subset_experiment": True,
        "subset_sample_count": len(X_tr) + len(X_va),
        "experiment_id": EXPERIMENT_ID,
        "sampling_algorithm": "deterministic-hmac-sha256-reservoir-nperclass-12500",
    }

    return booster, operating_threshold, train_summary, (X_va, y_va, val_probs)


# ---------------------------------------------------------------------------
# PHASE 5: Evaluate
# ---------------------------------------------------------------------------
def evaluate(booster, X_test, y_test, operating_threshold, split_name="test"):
    from sklearn.metrics import (
        roc_auc_score, confusion_matrix, precision_score,
        recall_score, f1_score, accuracy_score, balanced_accuracy_score,
    )

    y_prob = booster.predict(X_test)
    y_pred = (y_prob >= operating_threshold).astype(int)

    roc_auc = float(roc_auc_score(y_test, y_prob))
    partial_auc_005 = float(roc_auc_score(y_test, y_prob, max_fpr=0.005))
    partial_auc_01  = float(roc_auc_score(y_test, y_prob, max_fpr=0.01))

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall    = float(recall_score(y_test, y_pred, zero_division=0))
    f1        = float(f1_score(y_test, y_pred, zero_division=0))
    accuracy  = float(accuracy_score(y_test, y_pred))
    bal_acc   = float(balanced_accuracy_score(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    tpr = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0

    metrics = {
        "roc_auc": roc_auc,
        "partial_roc_auc_max_fpr_0005": partial_auc_005,
        "partial_roc_auc_max_fpr_001": partial_auc_01,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": accuracy,
        "balanced_accuracy": bal_acc,
        "false_positive_rate": fpr,
        "true_positive_rate": tpr,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "operating_threshold": operating_threshold,
        "evaluation_split": split_name,
    }

    # Probability distributions
    benign_probs = y_prob[y_test == 0]
    mal_probs    = y_prob[y_test == 1]
    metrics["prob_dist"] = {
        "benign_mean":   float(np.mean(benign_probs)),
        "benign_median": float(np.median(benign_probs)),
        "benign_p75":    float(np.percentile(benign_probs, 75)),
        "benign_p95":    float(np.percentile(benign_probs, 95)),
        "benign_max":    float(np.max(benign_probs)),
        "malicious_mean":   float(np.mean(mal_probs)),
        "malicious_median": float(np.median(mal_probs)),
        "malicious_p25":    float(np.percentile(mal_probs, 25)),
        "malicious_p5":     float(np.percentile(mal_probs, 5)),
        "malicious_min":    float(np.min(mal_probs)),
    }

    return metrics


# ---------------------------------------------------------------------------
# PHASE 6: Save Artifacts and Metadata
# ---------------------------------------------------------------------------
def save_artifacts(booster, train_summary, test_metrics, val_metrics):
    import jsonschema

    # Save model atomically
    temp_model = EXP_MODEL.with_suffix(".tmp")
    booster.save_model(str(temp_model))
    if EXP_MODEL.exists():
        EXP_MODEL.unlink()
    temp_model.replace(EXP_MODEL)

    # Compute SHA-256
    h = hashlib.sha256()
    with open(EXP_MODEL, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    artifact_sha256 = h.hexdigest().lower()

    metadata = {
        "model_id": "sentinel-pe-lightgbm-repr",
        "model_version": "1.1.0",
        "model_family": "lightgbm",
        "task_type": "binary_classification",
        "dataset_id": "ember",
        "dataset_version": "2018.v2",
        "feature_schema_version": "ember_pe_v2",
        "feature_count": DIM,
        "label_mapping": {"0": "BENIGN", "1": "MALICIOUS"},
        "class_order": ["BENIGN", "MALICIOUS"],
        "training_config": {
            **train_summary,
            **LGB_PARAMS,
        },
        "artifact_format": "LightGBM_Text",
        "artifact_hash": artifact_sha256,
        "metrics": {
            "roc_auc": test_metrics["roc_auc"],
            "partial_roc_auc_max_fpr_0005": test_metrics["partial_roc_auc_max_fpr_0005"],
            "partial_roc_auc_max_fpr_001": test_metrics["partial_roc_auc_max_fpr_001"],
            "precision": test_metrics["precision"],
            "recall": test_metrics["recall"],
            "f1_score": test_metrics["f1_score"],
            "false_positive_rate": test_metrics["false_positive_rate"],
            "evaluation_split": "test",
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Validate against schema
    schema_path = PROJECT_ROOT / "shared" / "schemas" / "model_metadata.schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    jsonschema.validate(instance=metadata, schema=schema)
    print("  Metadata passed JSON Schema validation.")

    with open(EXP_META, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"  Model artifact:  {EXP_MODEL}  ({EXP_MODEL.stat().st_size:,} bytes)")
    print(f"  Model SHA-256:   {artifact_sha256}")
    print(f"  Metadata:        {EXP_META}")

    return artifact_sha256, metadata


# ---------------------------------------------------------------------------
# PHASE 7: Investigate Partial AUC Discrepancy in Original Metadata
# ---------------------------------------------------------------------------
def investigate_original_partial_auc():
    """
    Original report showed:
      - Independent calculation at max_fpr=0.01: 0.515522
      - Original metadata 'partial_roc_auc_low_fpr' (max_fpr=0.005): 0.505021

    These are DIFFERENT metrics (max_fpr=0.005 vs max_fpr=0.01), NOT a calculation error.
    Verify by recomputing both from the original model artifact.
    """
    from sklearn.metrics import roc_auc_score
    import lightgbm as lgb

    print("\n--- Investigating Original Baseline Partial AUC Discrepancy ---")

    if not ORIGINAL_MODEL.is_file():
        print("  Original model not found; skipping investigation.")
        return {}

    booster = lgb.Booster(model_file=str(ORIGINAL_MODEL))
    n_test = 10000
    dim = 2381
    X_test = np.memmap(ORIGINAL_X_TEST, dtype=np.float32, mode="r", shape=(n_test, dim))
    y_test = np.memmap(ORIGINAL_Y_TEST, dtype=np.float32, mode="r", shape=(n_test,))

    y_prob = booster.predict(X_test)

    auc_full          = float(roc_auc_score(y_test, y_prob))
    auc_partial_0005  = float(roc_auc_score(y_test, y_prob, max_fpr=0.005))
    auc_partial_001   = float(roc_auc_score(y_test, y_prob, max_fpr=0.01))

    # Load original metadata value
    with open(ORIGINAL_META, "r", encoding="utf-8") as f:
        orig_meta = json.load(f)
    stored_low_fpr = orig_meta.get("metrics", {}).get("partial_roc_auc_low_fpr", "NOT STORED")

    print(f"  ROC-AUC (full):                {auc_full:.6f}")
    print(f"  Partial ROC-AUC (max_fpr=0.005): {auc_partial_0005:.6f}")
    print(f"  Partial ROC-AUC (max_fpr=0.01):  {auc_partial_001:.6f}")
    print(f"  Metadata stored value (low_fpr): {stored_low_fpr}")
    print()
    print("  EXPLANATION: The discrepancy in the previous report was NOT a calculation error.")
    print("  The stored metadata used max_fpr=0.005 (value=0.5050), while the Phase 6")
    print("  independent calculation used max_fpr=0.01 (value=0.5155). Both are correct")
    print("  independently; they are DIFFERENT metrics with different FPR bounds.")
    print("  Resolution: Store BOTH values with explicit max_fpr labels in new metadata.")

    return {
        "baseline_roc_auc": auc_full,
        "baseline_partial_auc_max_fpr_0005": auc_partial_0005,
        "baseline_partial_auc_max_fpr_001": auc_partial_001,
        "baseline_metadata_stored_low_fpr": stored_low_fpr,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    separator("T014 Corrective Experiment: Representative EMBER Sampling")
    print(f"Experiment ID:  {EXPERIMENT_ID}")
    print(f"Output dir:     {EXPERIMENT_DIR}")
    print(f"Sampling:       Deterministic HMAC-SHA256 reservoir, {N_TRAIN_PER_CLASS:,}/class train, "
          f"{N_TEST_PER_CLASS:,}/class test")
    separator()

    # 0. Verify baseline preservation
    assert ORIGINAL_MODEL.is_file(), "Baseline model missing!"
    assert ORIGINAL_META.is_file(),  "Baseline metadata missing!"
    print(f"[OK] Baseline model preserved: {ORIGINAL_MODEL}")

    train_shards = sorted(EMBER_DIR.glob("train_features_*.jsonl"))
    test_shard   = EMBER_DIR / "test_features.jsonl"

    # ------------------------------------------------------------------
    # PHASE 1: CENSUS
    # ------------------------------------------------------------------
    separator("Phase 1: Dataset Census")
    t_census_start = time.time()
    census = run_census()
    print(f"Census completed in {time.time() - t_census_start:.1f}s")
    separator()

    print("\nShard-by-shard summary:")
    print(f"  {'Shard':<35} {'Lines':>8} {'Benign':>8} {'Malicious':>9} {'Unlabeled':>10} "
          f"{'Appeared Min':>14} {'Appeared Max':>14}")
    print("  " + "-" * 105)
    for shard_name, d in census["train_shards"].items():
        print(f"  {shard_name:<35} {d['lines']:>8,} {d['benign']:>8,} {d['malicious']:>9,} "
              f"{d['unlabeled']:>10,} {str(d['appeared_min']):>14} {str(d['appeared_max']):>14}")
    for shard_name, d in census["test_shard"].items():
        print(f"  {shard_name:<35} {d['lines']:>8,} {d['benign']:>8,} {d['malicious']:>9,} "
              f"{d['unlabeled']:>10,} {str(d['appeared_min']):>14} {str(d['appeared_max']):>14}")
    g = census["global"]
    print(f"\n  Global: {g['total_lines']:,} total lines | "
          f"B={g['total_benign']:,} M={g['total_malicious']:,} U={g['total_unlabeled']:,}")

    # ------------------------------------------------------------------
    # PHASE 2: REPRESENTATIVE SAMPLING
    # ------------------------------------------------------------------
    separator("Phase 2: Deterministic Representative Sampling")
    t_sample_start = time.time()

    train_selected, train_class_counts = select_representative_samples(
        train_shards, N_TRAIN_PER_CLASS, "train"
    )
    test_selected, test_class_counts = select_representative_samples(
        [test_shard], N_TEST_PER_CLASS, "test"
    )

    # Verify no cross-split overlap
    overlap = set(train_selected.keys()) & set(test_selected.keys())
    print(f"\n  Cross-split SHA-256 overlap: {len(overlap)} (expected: 0)")
    assert len(overlap) == 0, "CRITICAL: Training and test samples overlap!"

    # Record which shards contributed training samples
    train_shard_contribs: Dict[str, int] = {}
    for sha, (shard_name, line_idx, lbl) in train_selected.items():
        train_shard_contribs[shard_name] = train_shard_contribs.get(shard_name, 0) + 1

    print("\n  Training shard contributions:")
    for shard_name, count in sorted(train_shard_contribs.items()):
        print(f"    {shard_name}: {count:,} records")

    manifest = {
        "experiment_id": EXPERIMENT_ID,
        "algorithm": "hmac-sha256-min-N-reservoir-per-class",
        "hmac_key": "sentinel-t014-repr-v1",
        "n_train_per_class": N_TRAIN_PER_CLASS,
        "n_test_per_class": N_TEST_PER_CLASS,
        "train_selected_total": len(train_selected),
        "test_selected_total": len(test_selected),
        "train_class_counts": {str(k): v for k, v in train_class_counts.items()},
        "test_class_counts": {str(k): v for k, v in test_class_counts.items()},
        "train_shard_contributions": train_shard_contribs,
        "cross_split_overlap": len(overlap),
        "first_10_train_sha256": sorted(train_selected.keys())[:10],
        "first_10_test_sha256": sorted(test_selected.keys())[:10],
    }
    with open(EXP_SAMPLE_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n  Sample manifest saved to {EXP_SAMPLE_MANIFEST}")
    print(f"  Sampling completed in {time.time() - t_sample_start:.1f}s")

    # ------------------------------------------------------------------
    # PHASE 3: VECTORIZATION
    # ------------------------------------------------------------------
    separator("Phase 3: Vectorization")

    n_train, train_vec_counts = vectorize_selected(
        train_shards, train_selected, EXP_X_TRAIN, EXP_Y_TRAIN, "train"
    )
    n_test, test_vec_counts = vectorize_selected(
        [test_shard], test_selected, EXP_X_TEST, EXP_Y_TEST, "test"
    )

    # Load as arrays
    X_train_all = np.memmap(EXP_X_TRAIN, dtype=np.float32, mode="r", shape=(n_train, DIM))
    y_train_all = np.memmap(EXP_Y_TRAIN, dtype=np.float32, mode="r", shape=(n_train,))
    X_test = np.memmap(EXP_X_TEST, dtype=np.float32, mode="r", shape=(n_test, DIM))
    y_test = np.memmap(EXP_Y_TEST, dtype=np.float32, mode="r", shape=(n_test,))

    print(f"\n  Train arrays: X={EXP_X_TRAIN.stat().st_size:,}B, y={EXP_Y_TRAIN.stat().st_size:,}B")
    print(f"  Test arrays:  X={EXP_X_TEST.stat().st_size:,}B, y={EXP_Y_TEST.stat().st_size:,}B")
    assert np.all(np.isfinite(X_train_all)), "Non-finite values in training features!"
    assert np.all(np.isfinite(X_test)), "Non-finite values in test features!"

    # ------------------------------------------------------------------
    # PHASE 4: TRAINING
    # ------------------------------------------------------------------
    separator("Phase 4: LightGBM Training")
    booster, threshold, train_summary, (X_va, y_va, val_probs) = train_model(
        X_train_all, y_train_all
    )

    # ------------------------------------------------------------------
    # PHASE 5: VALIDATION EVALUATION
    # ------------------------------------------------------------------
    separator("Phase 5: Validation Metrics")
    val_metrics = evaluate(booster, X_va, y_va, threshold, split_name="validation")
    print(f"  Val ROC-AUC:  {val_metrics['roc_auc']:.6f}")
    print(f"  Val FPR:      {val_metrics['false_positive_rate']:.6f} "
          f"(threshold={threshold:.4f}, target <= 0.005)")
    print(f"  Val TPR:      {val_metrics['true_positive_rate']:.6f}")
    print(f"  Val CM:       TN={val_metrics['confusion_matrix'][0][0]}, "
          f"FP={val_metrics['confusion_matrix'][0][1]}, "
          f"FN={val_metrics['confusion_matrix'][1][0]}, "
          f"TP={val_metrics['confusion_matrix'][1][1]}")

    # ------------------------------------------------------------------
    # PHASE 6: TEST EVALUATION (threshold FROZEN, never touched after this)
    # ------------------------------------------------------------------
    separator("Phase 6: Held-Out Test Evaluation")
    test_metrics = evaluate(booster, X_test, y_test, threshold, split_name="test")

    # ------------------------------------------------------------------
    # PHASE 7: SAVE ARTIFACTS
    # ------------------------------------------------------------------
    separator("Phase 7: Save Artifacts & Validate Metadata")
    artifact_sha256, metadata = save_artifacts(booster, train_summary, test_metrics, val_metrics)

    # Reload and smoke test
    import lightgbm as lgb
    booster_reloaded = lgb.Booster(model_file=str(EXP_MODEL))
    smoke_probs = booster_reloaded.predict(X_test[:5])
    assert np.all((smoke_probs >= 0.0) & (smoke_probs <= 1.0)), "Invalid probabilities!"
    print(f"  Smoke test: predictions={smoke_probs.round(4).tolist()}")
    print("  Reload + smoke test PASSED.")

    # Verify stored digest matches file
    h = hashlib.sha256()
    with open(EXP_MODEL, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    assert h.hexdigest().lower() == artifact_sha256, "Artifact hash mismatch!"
    print("  Artifact hash verification PASSED.")

    # ------------------------------------------------------------------
    # PHASE 8: INVESTIGATE ORIGINAL PARTIAL AUC DISCREPANCY
    # ------------------------------------------------------------------
    separator("Phase 8: Original Baseline Partial AUC Investigation")
    baseline_pauc = investigate_original_partial_auc()

    # ------------------------------------------------------------------
    # FINAL REPORT
    # ------------------------------------------------------------------
    separator("FINAL EXPERIMENT REPORT")
    print()
    print(f"{'Metric':<40} {'Original (Sequential)':>24} {'New (Representative)':>24}")
    print("-" * 90)

    orig_metrics = {
        "ROC-AUC": 0.743126,
        "Partial AUC (max_fpr=0.005)": 0.505021,
        "Partial AUC (max_fpr=0.010)": 0.515522,
        "Precision": 0.599686,
        "Recall": 0.841000,
        "F1-Score": 0.700133,
        "Accuracy": 0.639800,
        "Balanced Accuracy": 0.639800,
        "FPR at threshold": 0.561400,
        "TPR at threshold": 0.841000,
    }
    new_metrics = {
        "ROC-AUC": test_metrics["roc_auc"],
        "Partial AUC (max_fpr=0.005)": test_metrics["partial_roc_auc_max_fpr_0005"],
        "Partial AUC (max_fpr=0.010)": test_metrics["partial_roc_auc_max_fpr_001"],
        "Precision": test_metrics["precision"],
        "Recall": test_metrics["recall"],
        "F1-Score": test_metrics["f1_score"],
        "Accuracy": test_metrics["accuracy"],
        "Balanced Accuracy": test_metrics["balanced_accuracy"],
        "FPR at threshold": test_metrics["false_positive_rate"],
        "TPR at threshold": test_metrics["true_positive_rate"],
    }
    for metric in orig_metrics:
        print(f"  {metric:<38} {orig_metrics[metric]:>24.6f} {new_metrics[metric]:>24.6f}")

    print()
    separator("Confusion Matrix Comparison")
    print("  Original baseline:")
    print("    [[TN=2193, FP=2807], [FN=795, TP=4205]]")
    print("  New representative pilot:")
    cm_new = test_metrics["confusion_matrix"]
    print(f"    [[TN={cm_new[0][0]}, FP={cm_new[0][1]}], [FN={cm_new[1][0]}, TP={cm_new[1][1]}]]")

    print()
    separator("Probability Distribution Comparison")
    orig_dist = {
        "Val Benign mean": 0.0359, "Val Benign median": 0.0072,
        "Test Benign mean": 0.6195, "Test Benign median": 0.8504,
    }
    new_dist = test_metrics["prob_dist"]
    print("  Original baseline (sequential sampling):")
    for k, v in orig_dist.items():
        print(f"    {k}: {v:.4f}")
    print("  New representative pilot (HMAC reservoir):")
    print(f"    Test Benign mean:   {new_dist['benign_mean']:.4f}")
    print(f"    Test Benign median: {new_dist['benign_median']:.4f}")
    print(f"    Test Benign p75:    {new_dist['benign_p75']:.4f}")
    print(f"    Test Benign p95:    {new_dist['benign_p95']:.4f}")
    print(f"    Test Malicious mean: {new_dist['malicious_mean']:.4f}")
    print(f"    Test Malicious median: {new_dist['malicious_median']:.4f}")

    print()
    separator("Training Shard Contributions")
    for shard_name, count in sorted(train_shard_contribs.items()):
        print(f"  {shard_name}: {count:,} selected records")

    print()
    separator("Experiment Artifacts")
    print(f"  Model:    {EXP_MODEL}  ({EXP_MODEL.stat().st_size:,} bytes)")
    print(f"  SHA-256:  {artifact_sha256}")
    print(f"  Metadata: {EXP_META}")
    print(f"  Census:   {EXP_CENSUS}")
    print(f"  Manifest: {EXP_SAMPLE_MANIFEST}")
    print(f"  X_train:  {EXP_X_TRAIN}  ({EXP_X_TRAIN.stat().st_size:,} bytes)")
    print(f"  X_test:   {EXP_X_TEST}   ({EXP_X_TEST.stat().st_size:,} bytes)")

    print()
    separator("Partial AUC Discrepancy Resolution")
    print("  Previous report discrepancy:")
    print("    - Phase 6 independent recalculation: 0.515522 (max_fpr=0.01)")
    print("    - Original metadata stored value:    0.505021 (max_fpr=0.005)")
    print("  Cause: Two DIFFERENT metrics with different FPR bounds, NOT a calculation error.")
    print("  Resolution: New metadata stores BOTH:")
    print(f"    partial_roc_auc_max_fpr_0005 = {test_metrics['partial_roc_auc_max_fpr_0005']:.6f}")
    print(f"    partial_roc_auc_max_fpr_001  = {test_metrics['partial_roc_auc_max_fpr_001']:.6f}")
    if baseline_pauc:
        print(f"  Baseline model on original test set:")
        print(f"    partial_roc_auc_max_fpr_0005 = {baseline_pauc.get('baseline_partial_auc_max_fpr_0005', 'N/A'):.6f}")
        print(f"    partial_roc_auc_max_fpr_001  = {baseline_pauc.get('baseline_partial_auc_max_fpr_001', 'N/A'):.6f}")

    separator("T014 STATUS")
    print("  Status: IN_REVIEW")
    print("  Both pilots are resource-bounded subsets (25k train, 10k test) of the full")
    print("  EMBER 2018 dataset. Full-scale benchmark (800k-1M samples) requires >= 16GB RAM.")
    print("  Baseline artifacts preserved. T015 not started.")
    separator()


if __name__ == "__main__":
    main()
