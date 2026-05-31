"""
src/train.py
------------
Model training pipeline for phishing URL detection.

Responsibilities:
  1. Load and validate the dataset
  2. Preprocess / clean URLs
  3. Extract lexical features
  4. Train a Random Forest classifier
  5. Save the trained model to disk
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
import joblib
from tqdm import tqdm

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.features import extract_features, FEATURE_NAMES

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DATA_PATH  = "data/urls.csv"
DEFAULT_MODEL_PATH = "models/phishing_model.pkl"
RANDOM_STATE       = 42
TEST_SIZE          = 0.2


# ---------------------------------------------------------------------------
# Step 1 — Load Dataset
# ---------------------------------------------------------------------------

def load_dataset(filepath: str) -> pd.DataFrame:
    """
    Load and validate the phishing URL dataset.

    Expected CSV format (one of two common layouts):
      Layout A:  url, label          (label: 'phishing' / 'legitimate')
      Layout B:  url, type           (type:  'phishing' / 'benign')
      Layout C:  url, status         (status: 'phishing' / 'legitimate')

    Returns a DataFrame with exactly two columns: ['url', 'label']
    where label is 1 = phishing, 0 = safe.
    """
    print(f"[1/5] Loading dataset from: {filepath}")

    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"\n❌ Dataset not found at '{filepath}'.\n"
            "Please download one of these datasets and place it in data/:\n"
            "  • Kaggle: https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls\n"
            "    Save as: data/urls.csv  (columns: URL, Label)\n"
            "  • PhiUSIIL (UCI): https://archive.ics.uci.edu/dataset/967\n"
            "  • See README.md for full list.\n"
        )

    df = pd.read_csv(filepath)
    print(f"   Raw shape: {df.shape}")
    print(f"   Columns:   {list(df.columns)}")

    # --- Normalize column names ---
    df.columns = [c.strip().lower() for c in df.columns]

    # Find the URL column
    url_col = None
    for candidate in ["url", "urls", "link", "domain"]:
        if candidate in df.columns:
            url_col = candidate
            break
    if url_col is None:
        raise ValueError(f"Cannot find URL column. Got columns: {list(df.columns)}")

    # Find the label column
    label_col = None
    for candidate in ["label", "type", "status", "class", "phishing"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError(f"Cannot find label column. Got columns: {list(df.columns)}")

    df = df[[url_col, label_col]].copy()
    df.columns = ["url", "label"]

    return df


# ---------------------------------------------------------------------------
# Step 2 — Preprocess
# ---------------------------------------------------------------------------

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean the dataset:
    - Drop nulls
    - Convert labels to binary integers (1=phishing, 0=safe)
    - Remove duplicate URLs
    - Basic URL sanity check
    """
    print("[2/5] Preprocessing dataset...")

    initial_count = len(df)

    # Drop nulls
    df = df.dropna(subset=["url", "label"])

    # Strip whitespace
    df["url"]   = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()

    # Drop empty URLs
    df = df[df["url"].str.len() > 0]

    # ── NORMALIZE URLs ──────────────────────────────────────────────
    # Add http:// prefix if missing — prevents the model from learning
    # the dataset's protocol bias (most legit URLs in Kaggle have https,
    # most phishing URLs don't, which causes false shortcuts).
    def normalize_url(u):
        u = u.lower().strip()
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        return u
    df["url"] = df["url"].apply(normalize_url)

    # Normalize labels to binary
    phishing_values = {"phishing", "bad", "1", "malicious", "spam"}
    safe_values     = {"benign", "legitimate", "good", "0", "safe", "clean"}

    def map_label(val):
        if val in phishing_values:
            return 1
        elif val in safe_values:
            return 0
        else:
            return None  # Unknown label — will be dropped

    df["label"] = df["label"].apply(map_label)
    unknown_count = df["label"].isna().sum()
    if unknown_count > 0:
        print(f"   ⚠️  Dropping {unknown_count} rows with unrecognized labels.")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    # Remove duplicates
    df = df.drop_duplicates(subset=["url"])

    final_count = len(df)
    print(f"   Rows before: {initial_count:,}  →  after cleaning: {final_count:,}")
    print(f"   Label distribution:\n{df['label'].value_counts().to_string()}")
    print(f"   Phishing ratio: {df['label'].mean():.1%}")

    return df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Step 3 — Feature Extraction
# ---------------------------------------------------------------------------

def build_feature_matrix(df: pd.DataFrame) -> tuple:
    """
    Run extract_features() on every URL and return (X, y).

    Returns
    -------
    X : pd.DataFrame  shape (n_samples, n_features)
    y : pd.Series     shape (n_samples,)  — binary labels
    """
    print(f"[3/5] Extracting features from {len(df):,} URLs...")

    rows = []
    for url in tqdm(df["url"], desc="   Feature extraction", unit="url"):
        rows.append(extract_features(url))

    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = df["label"].reset_index(drop=True)

    print(f"   Feature matrix shape: {X.shape}")
    return X, y


# ---------------------------------------------------------------------------
# Step 4 — Train Model
# ---------------------------------------------------------------------------

def train_model(X_train: pd.DataFrame, y_train: pd.Series) -> RandomForestClassifier:
    """
    Train a Random Forest classifier.

    Why Random Forest?
    ------------------
    ✓ Handles mixed feature scales without normalization
    ✓ Naturally resistant to overfitting (ensemble of trees)
    ✓ Provides feature importances out-of-the-box
    ✓ Fast training and inference
    ✓ Works well with small to medium datasets
    ✓ Interpretable enough for security use cases
    """
    print("[4/5] Training Random Forest classifier...")

    model = RandomForestClassifier(
        n_estimators=300,          # More trees = more stable
        max_depth=25,              # Cap depth to reduce overfitting on dataset quirks
        min_samples_split=10,      # Need more samples to split
        min_samples_leaf=5,        # Larger leaves = better generalization
        max_features="sqrt",
        class_weight=None,         # Use natural class distribution (no overcorrection)
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    # Quick cross-validation check on training set
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy", n_jobs=-1)
    print(f"   5-Fold CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    return model


# ---------------------------------------------------------------------------
# Step 5 — Save Model
# ---------------------------------------------------------------------------

def save_model(model: RandomForestClassifier, path: str):
    """Save the trained model using joblib (preferred over pickle for sklearn)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    size_kb = os.path.getsize(path) / 1024
    print(f"[5/5] Model saved → {path}  ({size_kb:.1f} KB)")


def load_model(path: str) -> RandomForestClassifier:
    """Load a previously saved model."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"No trained model found at '{path}'. Run training first.")
    return joblib.load(path)


# ---------------------------------------------------------------------------
# Full Training Pipeline
# ---------------------------------------------------------------------------

def run_training_pipeline(
    data_path:  str = DEFAULT_DATA_PATH,
    model_path: str = DEFAULT_MODEL_PATH,
    sample_size: int = None,
) -> tuple:
    """
    End-to-end training pipeline.

    Parameters
    ----------
    data_path   : path to the CSV dataset
    model_path  : where to save the trained model
    sample_size : optional — limit rows for fast testing (None = use all)

    Returns
    -------
    model      : trained RandomForestClassifier
    X_test     : test feature matrix
    y_test     : test labels
    """
    print("\n" + "="*60)
    print("  PHISHING DETECTOR — TRAINING PIPELINE")
    print("="*60)

    # Load
    df = load_dataset(data_path)
    if sample_size:
        df = df.sample(n=min(sample_size, len(df)), random_state=RANDOM_STATE)
        print(f"   (Sampled {len(df):,} rows for testing)")

    # Preprocess
    df = preprocess(df)

    # Feature extraction
    X, y = build_feature_matrix(df)

    # Train/test split — stratified to preserve class ratio
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    print(f"   Train: {len(X_train):,} samples  |  Test: {len(X_test):,} samples")

    # Train
    model = train_model(X_train, y_train)

    # Save
    save_model(model, model_path)

    print("\n✅ Training complete!\n")
    return model, X_test, y_test


if __name__ == "__main__":
    run_training_pipeline()
