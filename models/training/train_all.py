import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.dummy import DummyClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, precision_score,
    recall_score, f1_score, accuracy_score
)
from models.training.dataset_builder import DatasetBuilder
from features.feature_pipeline import FeaturePipeline

def train_models():
    """
    Trains Supervised Random Forest and Unsupervised Isolation Forest models
    on realistic synthetic dataset, using session-group splitting to prevent leakage.
    Prints honest evaluation metrics (Macro F1, Weighted F1, Confusion Matrix, FPR/FNR).
    """
    print("==================================================================")
    print("        OracleShield ML Pipeline Training & Evaluation            ")
    print("==================================================================")
    print("DISCLOSURE: Evaluation performed on synthetic feature distribution.")

    builder = DatasetBuilder()
    df = builder.generate_synthetic_dataset(samples_per_class=350)

    feature_cols = FeaturePipeline.FEATURE_NAMES
    X = df[feature_cols]
    y = df["class_id"]
    groups = df["session_group"]

    # Session/Group-based splitting (70% Train, 15% Val, 15% Test)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=42)
    train_idx, temp_idx = next(gss.split(X, y, groups))

    X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
    X_temp, y_temp = X.iloc[temp_idx], y.iloc[temp_idx]
    groups_temp = groups.iloc[temp_idx]

    gss_val = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=42)
    val_idx, test_idx = next(gss_val.split(X_temp, y_temp, groups_temp))

    X_test, y_test = X_temp.iloc[test_idx], y_temp.iloc[test_idx]

    print(f"\nDataset Breakdown:")
    print(f"  Total Samples:     {len(df)}")
    print(f"  Training Set:      {len(X_train)} samples")
    print(f"  Test Set:          {len(X_test)} samples ({len(np.unique(groups.iloc[temp_idx].iloc[test_idx]))} distinct sessions)")
    print(f"  Number of Classes: {len(np.unique(y))}")

    # Baseline Classifier (Majority Class Baseline)
    dummy = DummyClassifier(strategy="most_frequent")
    dummy.fit(X_train, y_train)
    dummy_acc = dummy.score(X_test, y_test)
    print(f"\nMajority Class Baseline Accuracy: {dummy_acc:.4f}")

    # Train Supervised Random Forest Classifier
    rf_model = RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42)
    rf_model.fit(X_train, y_train)

    y_pred = rf_model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    macro_prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    cm = confusion_matrix(y_test, y_pred)
    fp = cm.sum(axis=0) - np.diag(cm)
    fn = cm.sum(axis=1) - np.diag(cm)
    tp = np.diag(cm)
    tn = cm.sum() - (fp + fn + tp)

    fpr = np.mean(fp / (fp + tn + 1e-6))
    fnr = np.mean(fn / (fn + tp + 1e-6))

    print("\n--- Supervised Random Forest Evaluation ---")
    print(f"  Accuracy:     {acc:.4f}")
    print(f"  Macro Prec:   {macro_prec:.4f}")
    print(f"  Macro Recall: {macro_rec:.4f}")
    print(f"  Macro F1:     {macro_f1:.4f}")
    print(f"  Weighted F1:  {weighted_f1:.4f}")
    print(f"  Mean FPR:     {fpr:.4f}")
    print(f"  Mean FNR:     {fnr:.4f}")

    print("\nConfusion Matrix:")
    print(cm)

    # Save trained models
    out_dir = os.path.abspath("models/trained")
    os.makedirs(out_dir, exist_ok=True)

    rf_path = os.path.join(out_dir, "oracle_shield_rf.joblib")
    joblib.dump(rf_model, rf_path)
    print(f"\n[Saved] Supervised RF Model -> {rf_path}")

    # Train Isolation Forest Anomaly Model on Benign traffic
    iso_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    benign_X = X_train[y_train == 0]
    iso_model.fit(benign_X)

    iso_path = os.path.join(out_dir, "oracle_shield_isoforest.joblib")
    joblib.dump(iso_model, iso_path)
    print(f"[Saved] Isolation Forest Model -> {iso_path}")
    print("==================================================================\n")

if __name__ == "__main__":
    train_models()
