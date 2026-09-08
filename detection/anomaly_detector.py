import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult
from features.feature_pipeline import FeaturePipeline

class AnomalyDetector(BaseDetector):
    """
    Unsupervised Anomaly Detector loading serialized Isolation Forest model.
    Identifies previously unseen, anomalous flow behaviors flagging them as UNKNOWN_ANOMALY.
    """

    def __init__(self, model_path: str = "models/trained/oracle_shield_isoforest.joblib"):
        super().__init__(name="AnomalyDetector", version="isoforest-v1.0")
        self.model_path = os.path.abspath(model_path)
        self.pipeline = FeaturePipeline()
        self.model = None
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_loaded = True
            except Exception:
                self.is_loaded = False
        else:
            self.is_loaded = False

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.is_loaded or self.model is None:
            return None

        vector = [float(flow_features.get(name, 0.0)) for name in self.pipeline.FEATURE_NAMES]
        X = pd.DataFrame([vector], columns=self.pipeline.FEATURE_NAMES)

        try:
            score = float(self.model.decision_function(X)[0])
            prediction = int(self.model.predict(X)[0])  # -1 = anomaly, 1 = normal
        except Exception:
            return None

        if prediction == -1:
            confidence = min(0.92, 0.65 + abs(score) * 0.5)
            return DetectionResult(
                threat_class="UNKNOWN_ANOMALY",
                detected=True,
                confidence=round(confidence, 2),
                severity="MEDIUM",
                evidence={
                    "anomaly_score": round(score, 4),
                    "detector_source": "ISOLATION_FOREST",
                    "reason": "Traffic behavior significantly deviates from learned baseline"
                },
                contributing_features={
                    "isolation_depth": 0.60,
                    "statistical_distance": 0.40
                },
                model_version=self.version
            )

        return None
