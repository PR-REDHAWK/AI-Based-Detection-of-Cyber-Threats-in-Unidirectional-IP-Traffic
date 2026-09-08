import numpy as np
from typing import Dict, Any, Optional
from sklearn.ensemble import IsolationForest
from detection.base_detector import BaseDetector, DetectionResult
from features.feature_pipeline import FeaturePipeline

class AnomalyDetector(BaseDetector):
    """
    Unsupervised Anomaly Detector using Isolation Forest.
    Identifies previously unseen, anomalous flow behaviors flagging them as UNKNOWN_ANOMALY.
    """

    def __init__(self, contamination: float = 0.05):
        super().__init__(name="AnomalyDetector", version="isoforest-v1.0")
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self.pipeline = FeaturePipeline()
        self.is_trained = False
        self._fit_dummy_baseline()

    def _fit_dummy_baseline(self):
        """Fits initial baseline on synthetic benign vectors."""
        dummy_data = np.random.normal(loc=1.0, scale=0.2, size=(200, len(self.pipeline.FEATURE_NAMES)))
        self.model.fit(dummy_data)
        self.is_trained = True

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.is_trained:
            return None

        vector = np.array([[float(flow_features.get(name, 0.0)) for name in self.pipeline.FEATURE_NAMES]], dtype=np.float32)
        score = float(self.model.decision_function(vector)[0])
        prediction = int(self.model.predict(vector)[0])  # -1 = anomaly, 1 = normal

        if prediction == -1:
            confidence = min(0.92, 0.65 + abs(score) * 0.5)
            return DetectionResult(
                threat_class="UNKNOWN_ANOMALY",
                detected=True,
                confidence=round(confidence, 2),
                severity="MEDIUM",
                evidence={
                    "anomaly_score": round(score, 4),
                    "reason": "Traffic behavior significantly deviates from learned baseline"
                },
                contributing_features={
                    "isolation_depth": 0.60,
                    "statistical_distance": 0.40
                },
                model_version=self.version
            )

        return None
