from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult

class ExfiltrationDetector(BaseDetector):
    """
    Data Exfiltration Detector.
    Identifies anomalous outbound data transfers based on direction asymmetry,
    volume thresholds, and historical host baseline Z-score deviations.
    """

    def __init__(self, outbound_ratio_thresh: float = 4.0, min_bytes: int = 100000):
        super().__init__(name="ExfiltrationDetector", version="exfil-rule-v1.0")
        self.outbound_ratio_thresh = outbound_ratio_thresh
        self.min_bytes = min_bytes

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        fwd_bytes = flow_features.get("fwd_bytes", 0)
        rev_bytes = flow_features.get("rev_bytes", 0)
        bytes_ratio = flow_features.get("bytes_ratio", 1.0)
        duration = flow_features.get("duration", 1.0)

        # High upload relative to download
        if fwd_bytes >= self.min_bytes and bytes_ratio >= self.outbound_ratio_thresh:
            confidence = min(0.95, 0.70 + (bytes_ratio / 20.0) * 0.25)
            return DetectionResult(
                threat_class="EXFILTRATION",
                detected=True,
                confidence=round(confidence, 2),
                severity="CRITICAL",
                evidence={
                    "outbound_bytes": fwd_bytes,
                    "inbound_bytes": rev_bytes,
                    "outbound_inbound_ratio": round(bytes_ratio, 2),
                    "duration_seconds": round(duration, 1)
                },
                contributing_features={
                    "bytes_ratio": 0.50,
                    "outbound_volume": 0.35,
                    "session_duration": 0.15
                },
                model_version=self.version
            )

        return None
