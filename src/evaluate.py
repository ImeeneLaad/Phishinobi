"""
src/evaluate.py
---------------
Model evaluation utilities.

Generates a full report including:
  - Classification metrics (accuracy, precision, recall, F1)
  - Confusion matrix
  - Feature importances
  - Saves report to reports/ directory
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend (safe in all environments)
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.features import FEATURE_NAMES

REPORTS_DIR = "reports"


# ---------------------------------------------------------------------------
# Core Evaluation
# ---------------------------------------------------------------------------

def evaluate_model(model, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    """
    Compute all evaluation metrics for the model on the test set.

    Returns a dict with all scores (also prints a formatted summary).
    """
    print("\n" + "="*60)
    print("  MODEL EVALUATION")
    print("="*60)

    y_pred   = model.predict(X_test)
    y_proba  = model.predict_proba(X_test)[:, 1]  # Probability of phishing

    # Core metrics
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred)

    print(f"\n  Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  AUC-ROC   : {auc:.4f}")

    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    print("  Confusion Matrix:")
    print(f"    TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"    FN={cm[1][0]:,}  TP={cm[1][1]:,}")

    tn, fp, fn, tp = cm.ravel()
    print(f"\n  False Positive Rate: {fp/(fp+tn):.4f}  (legit URLs flagged as phishing)")
    print(f"  False Negative Rate: {fn/(fn+tp):.4f}  (phishing URLs missed)")

    return {
        "accuracy":  acc,
        "precision": prec,
        "recall":    rec,
        "f1":        f1,
        "auc_roc":   auc,
        "confusion_matrix": cm.tolist(),
        "false_positive_rate": fp / (fp + tn),
        "false_negative_rate": fn / (fn + tp),
    }


# ---------------------------------------------------------------------------
# Visualizations
# ---------------------------------------------------------------------------

def plot_confusion_matrix(model, X_test, y_test, save_dir: str = REPORTS_DIR):
    """Save a styled confusion matrix heatmap."""
    os.makedirs(save_dir, exist_ok=True)

    y_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt=",d",
        cmap="Blues",
        xticklabels=["Safe", "Phishing"],
        yticklabels=["Safe", "Phishing"],
        ax=ax,
    )
    ax.set_title("Confusion Matrix", fontsize=14, fontweight="bold")
    ax.set_ylabel("Actual Label")
    ax.set_xlabel("Predicted Label")

    path = os.path.join(save_dir, "confusion_matrix.png")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()
    print(f"   Saved: {path}")


def plot_feature_importances(model, save_dir: str = REPORTS_DIR, top_n: int = 15):
    """Save a horizontal bar chart of top feature importances."""
    os.makedirs(save_dir, exist_ok=True)

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]
    top_names  = [FEATURE_NAMES[i] for i in indices]
    top_values = importances[indices]

    fig, ax = plt.subplots(figsize=(8, 6))
    colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, top_n))
    ax.barh(range(top_n), top_values[::-1], color=colors[::-1])
    ax.set_yticks(range(top_n))
    ax.set_yticklabels(top_names[::-1], fontsize=10)
    ax.set_xlabel("Importance Score")
    ax.set_title(f"Top {top_n} Feature Importances", fontsize=14, fontweight="bold")

    path = os.path.join(save_dir, "feature_importances.png")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()
    print(f"   Saved: {path}")


def plot_roc_curve(model, X_test, y_test, save_dir: str = REPORTS_DIR):
    """Save the ROC curve plot."""
    os.makedirs(save_dir, exist_ok=True)

    y_proba = model.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc = roc_auc_score(y_test, y_proba)

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, color="#e63946", lw=2, label=f"AUC = {auc:.4f}")
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random (AUC=0.5)")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right")

    path = os.path.join(save_dir, "roc_curve.png")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()
    print(f"   Saved: {path}")


# ---------------------------------------------------------------------------
# Save JSON Report
# ---------------------------------------------------------------------------

def save_report(metrics: dict, save_dir: str = REPORTS_DIR):
    """Save evaluation metrics as a JSON report."""
    os.makedirs(save_dir, exist_ok=True)
    path = os.path.join(save_dir, "evaluation_report.json")

    # Make serializable
    metrics_out = {}
    for k, v in metrics.items():
        if isinstance(v, (np.floating, np.integer)):
            metrics_out[k] = float(v)
        else:
            metrics_out[k] = v

    with open(path, "w") as f:
        json.dump(metrics_out, f, indent=2)
    print(f"   Saved: {path}")


# ---------------------------------------------------------------------------
# Full Evaluation Run
# ---------------------------------------------------------------------------

def run_full_evaluation(model, X_test, y_test, save_dir: str = REPORTS_DIR):
    """Run all evaluations and save all reports/charts."""
    print("\n[Evaluation] Running full evaluation suite...")

    metrics = evaluate_model(model, X_test, y_test)

    print("\n[Evaluation] Generating visualizations...")
    plot_confusion_matrix(model, X_test, y_test, save_dir)
    plot_feature_importances(model, save_dir)
    plot_roc_curve(model, X_test, y_test, save_dir)
    save_report(metrics, save_dir)

    print(f"\n✅ All reports saved to: {save_dir}/")
    return metrics


if __name__ == "__main__":
    # Requires a trained model — run train.py first
    from src.train import load_model, run_training_pipeline
    model, X_test, y_test = run_training_pipeline()
    run_full_evaluation(model, X_test, y_test)
