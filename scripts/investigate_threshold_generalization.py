"""Detailed investigation into threshold selection, validation vs test generalization, and FPR discrepancy."""

import json
from pathlib import Path
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

model_path = Path(".data/models/sentinel-pe-lightgbm.txt")
meta_path = Path(".data/models/sentinel-pe-lightgbm_metadata.json")
metadata = json.loads(meta_path.read_text(encoding="utf-8"))
booster = lgb.Booster(model_file=str(model_path))

# Load data
n_train = 25000
n_test = 10000
dim = 2381

X_train = np.memmap(".data/ember/X_train.dat", dtype=np.float32, mode="r", shape=(n_train, dim))
y_train = np.memmap(".data/ember/y_train.dat", dtype=np.float32, mode="r", shape=(n_train,))

X_test = np.memmap(".data/ember/X_test.dat", dtype=np.float32, mode="r", shape=(n_test, dim))
y_test = np.memmap(".data/ember/y_test.dat", dtype=np.float32, mode="r", shape=(n_test,))

# Re-create validation split using exact training seed and parameters
X_tr, X_va, y_tr, y_va = train_test_split(
    X_train,
    y_train,
    test_size=0.2,
    random_state=42,
    stratify=y_train,
)

val_prob = booster.predict(X_va)
test_prob = booster.predict(X_test)
threshold = metadata["training_config"]["operating_threshold"]

# 1. Validation metrics at threshold 0.7100
val_pred = (val_prob >= threshold).astype(int)
cm_val = confusion_matrix(y_va, val_pred, labels=[0, 1])
tn_v, fp_v, fn_v, tp_v = cm_val.ravel()
fpr_val = float(fp_v / (fp_v + tn_v))
tpr_val = float(tp_v / (tp_v + fn_v))
prec_val = float(precision_score(y_va, val_pred, pos_label=1, zero_division=0))
rec_val = float(recall_score(y_va, val_pred, pos_label=1, zero_division=0))
f1_val = float(f1_score(y_va, val_pred, pos_label=1, zero_division=0))
roc_auc_val = float(roc_auc_score(y_va, val_prob))

print("=== VALIDATION SPLIT PERFORMANCE (at threshold = 0.7100) ===")
print("Validation samples:  ", len(y_va))
print("  Benign (0):        ", int(np.sum(y_va == 0)))
print("  Malicious (1):     ", int(np.sum(y_va == 1)))
print("Validation ROC-AUC:  ", f"{roc_auc_val:.6f}")
print("Validation FPR:      ", f"{fpr_val:.6f} ({fp_v}/{fp_v + tn_v})")
print("Validation TPR:      ", f"{tpr_val:.6f} ({tp_v}/{tp_v + fn_v})")
print("Validation Precision:", f"{prec_val:.6f}")
print("Validation Recall:   ", f"{rec_val:.6f}")
print("Validation F1:       ", f"{f1_val:.6f}")
print("Validation Confusion Matrix: [[TN=", tn_v, ", FP=", fp_v, "], [FN=", fn_v, ", TP=", tp_v, "]]")

# 2. Threshold Search Audit on Validation Set
print("\n=== THRESHOLD SEARCH AUDIT ON VALIDATION SET ===")
thresholds = np.linspace(0.1, 0.99, 90)
low_fpr_candidates = []
for th in thresholds:
    p_bin = (val_prob >= th).astype(int)
    cm_t = confusion_matrix(y_va, p_bin, labels=[0, 1])
    tn_t, fp_t, fn_t, tp_t = cm_t.ravel()
    fpr_t = fp_t / (fp_t + tn_t)
    f1_t = f1_score(y_va, p_bin, zero_division=0)
    if fpr_t <= 0.005:
        low_fpr_candidates.append((th, f1_t, fpr_t, tp_t / (tp_t + fn_t)))

print(f"Total candidate thresholds evaluated: {len(thresholds)}")
print(f"Candidate thresholds meeting FPR <= 0.005 on validation: {len(low_fpr_candidates)}")
if low_fpr_candidates:
    low_fpr_candidates.sort(key=lambda x: x[1], reverse=True)
    best_th, best_f1, best_fpr, best_tpr = low_fpr_candidates[0]
    print(f"Top low-FPR candidate: threshold={best_th:.4f}, F1={best_f1:.4f}, FPR={best_fpr:.6f}, TPR={best_tpr:.4f}")

# 3. Probability Distribution Analysis
print("\n=== PROBABILITY DISTRIBUTION COMPARISON ===")
val_benign_probs = val_prob[y_va == 0]
val_mal_probs = val_prob[y_va == 1]
test_benign_probs = test_prob[y_test == 0]
test_mal_probs = test_prob[y_test == 1]

print("Validation Benign (y=0) probs:  mean=", f"{val_benign_probs.mean():.4f}", "median=", f"{np.median(val_benign_probs):.4f}", "max=", f"{val_benign_probs.max():.4f}")
print("Validation Malicious (y=1) probs: mean=", f"{val_mal_probs.mean():.4f}", "median=", f"{np.median(val_mal_probs):.4f}", "min=", f"{val_mal_probs.min():.4f}")
print("Test Benign (y=0) probs:        mean=", f"{test_benign_probs.mean():.4f}", "median=", f"{np.median(test_benign_probs):.4f}", "max=", f"{test_benign_probs.max():.4f}")
print("Test Malicious (y=1) probs:       mean=", f"{test_mal_probs.mean():.4f}", "median=", f"{np.median(test_mal_probs):.4f}", "min=", f"{test_mal_probs.min():.4f}")

# Distribution percentiles
print("\nPercentiles of Predicted Probabilities:")
p_levels = [1, 5, 25, 50, 75, 95, 99]
print("Percentile:       ", "\t".join(f"{p}%" for p in p_levels))
print("Val Benign:       ", "\t".join(f"{np.percentile(val_benign_probs, p):.4f}" for p in p_levels))
print("Test Benign:      ", "\t".join(f"{np.percentile(test_benign_probs, p):.4f}" for p in p_levels))
print("Val Malicious:    ", "\t".join(f"{np.percentile(val_mal_probs, p):.4f}" for p in p_levels))
print("Test Malicious:   ", "\t".join(f"{np.percentile(test_mal_probs, p):.4f}" for p in p_levels))
