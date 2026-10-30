"""Independent audit and metric reproduction script for T014 model artifacts."""

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

model_path = Path(".data/models/sentinel-pe-lightgbm.txt")
meta_path = Path(".data/models/sentinel-pe-lightgbm_metadata.json")
metadata = json.loads(meta_path.read_text(encoding="utf-8"))

booster = lgb.Booster(model_file=str(model_path))

n_test = 10000
dim = 2381
X_test = np.memmap(".data/ember/X_test.dat", dtype=np.float32, mode="r", shape=(n_test, dim))
y_test = np.memmap(".data/ember/y_test.dat", dtype=np.float32, mode="r", shape=(n_test,))

y_prob = booster.predict(X_test)
threshold = metadata["training_config"]["operating_threshold"]
y_pred = (y_prob >= threshold).astype(int)

roc_auc = float(roc_auc_score(y_test, y_prob))
partial_roc_auc = float(roc_auc_score(y_test, y_prob, max_fpr=0.005))
precision = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
recall = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))
acc = float(accuracy_score(y_test, y_pred))
bal_acc = float(balanced_accuracy_score(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
tn, fp, fn, tp = cm.ravel()
fpr = float(fp / (fp + tn))
tpr = float(tp / (tp + fn))

print("=== INDEPENDENT REPRODUCTION RESULTS ===")
print("Test samples:        ", len(y_test))
print("Benign (0) count:    ", int(np.sum(y_test == 0)))
print("Malicious (1) count: ", int(np.sum(y_test == 1)))
print("Frozen Threshold:    ", threshold)
print("ROC-AUC:             ", f"{roc_auc:.6f}")
print("Partial ROC-AUC:     ", f"{partial_roc_auc:.6f}")
print("Precision:           ", f"{precision:.6f}")
print("Recall:              ", f"{recall:.6f}")
print("F1 Score:            ", f"{f1:.6f}")
print("Accuracy:            ", f"{acc:.6f}")
print("Balanced Accuracy:   ", f"{bal_acc:.6f}")
print("FPR:                 ", f"{fpr:.6f}")
print("TPR:                 ", f"{tpr:.6f}")
print("Confusion Matrix:    ", f"[[TN={tn}, FP={fp}], [FN={fn}, TP={tp}]]")

sm = metadata["metrics"]
print("\n=== COMPARISON WITH PERSISTED METADATA ===")
print("Saved ROC-AUC:  ", f"{sm['roc_auc']:.6f}", "Diff:", abs(roc_auc - sm['roc_auc']))
print("Saved Precision:", f"{sm['precision']:.6f}", "Diff:", abs(precision - sm['precision']))
print("Saved Recall:   ", f"{sm['recall']:.6f}", "Diff:", abs(recall - sm['recall']))
print("Saved F1:       ", f"{sm['f1_score']:.6f}", "Diff:", abs(f1 - sm['f1_score']))
print("Saved FPR:      ", f"{sm['false_positive_rate']:.6f}", "Diff:", abs(fpr - sm['false_positive_rate']))
