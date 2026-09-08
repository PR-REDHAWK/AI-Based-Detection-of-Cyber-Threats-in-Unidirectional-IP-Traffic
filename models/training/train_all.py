import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score
from models.training.dataset_builder import DatasetBuilder
from features.feature_pipeline import FeaturePipeline

def train_models():
    """
    Trains Supervised Random Forest and Unsupervised Isolation Forest models,
    evaluating Precision, Recall, F1, FPR, FNR, and serializing models using joblib.
    """
    builder = DatasetBuilder()
    df = builder.generate_synthetic_dataset(samples_per_class=300)

    feature_cols = FeaturePipeline.FEATURE_NAMES
    X = df[feature_cols]
    y = df["class_id"]

    # Session/capture-based split (70% train, 15% val, 15% test)
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    # Train Supervised Random Forest Classifier
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf_model.fit(X_train, y_train)

    y_pred = rf_model.predict(X_test)

    precision = precision_score(y_test, y_pred, average="macro")
    recall = recall_score(y_test, y_pred, average="macro")
    f1 = f1_score(y_test, y_pred, average="macro")

    cm = confusion_matrix(y_test, y_pred)
    fp = cm.sum(axis=0) - np.diag(cm)
    fn = cm.sum(axis=1) - np.diag(cm)
    tp = np.diag(cm)
    tn = cm.sum() - (fp + fn + tp)

    fpr = np.mean(fp / (fp + tn + 1e-6))
    fnr = np.mean(fn / (fn + tp + 1e-6))

    print(f"=== OracleShield ML Evaluation Results ===")
    print(f"Accuracy:  {rf_model.score(X_test, y_test):.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"FNR:       {fnr:.4f}")

    # Ensure output directory exists
    out_dir = os.path.abspath("models/trained")
    os.makedirs(out_dir, exist_ok=True)

    # Serialize model and feature names
    joblib.dump(rf_model, os.path.join(out_dir, "oracle_shield_rf.joblib"))
    print(f"Saved trained Random Forest model to: {os.path.join(out_dir, 'oracle_shield_rf.joblib')}")

    # Train Isolation Forest Anomaly Model
    iso_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    benign_X = X_train[y_train == 0]
    iso_model.fit(benign_X)
    joblib.dump(iso_model, os.path.join(out_dir, "oracle_shield_isoforest.joblib"))
    print(f"Saved trained Isolation Forest model to: {os.path.join(out_dir, 'oracle_shield_isoforest.joblib')}")

if __name__ == "__main__":
    train_models()
