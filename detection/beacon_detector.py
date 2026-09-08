from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult

class BeaconDetector(BaseDetector):
    """
    Botnet Command & Control (C2) Beacon Detector.
    Identifies periodic, highly regular connection patterns to external IPs.
    """

    def __init__(self, min_periodicity: float = 0.80, max_iat_std: float = 1.5):
        super().__init__(name="BeaconDetector", version="c2-rule-v1.0")
        self.min_periodicity = min_periodicity
        self.max_iat_std = max_iat_std

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        total_pkts = flow_features.get("total_packets", 0)
        if total_pkts < 4:
            return None  # Insufficient packets for periodicity estimation

        periodicity = flow_features.get("periodicity_score", 0.0)
        mean_iat = flow_features.get("mean_iat", 0.0)
        std_iat = flow_features.get("std_iat", 999.0)

        if periodicity >= self.min_periodicity and std_iat <= self.max_iat_std and mean_iat > 1.0:
            confidence = min(0.98, 0.65 + periodicity * 0.30)
            return DetectionResult(
                threat_class="C2_BEACONING",
                detected=True,
                confidence=round(confidence, 2),
                severity="HIGH",
                evidence={
                    "periodicity_score": round(periodicity, 3),
                    "mean_interarrival_seconds": round(mean_iat, 2),
                    "interarrival_std_seconds": round(std_iat, 3),
                    "packet_count": total_pkts,
                    "destination_ip": flow_features.get("responder_ip")
                },
                contributing_features={
                    "periodicity_score": 0.55,
                    "interarrival_std": 0.30,
                    "destination_concentration": 0.15
                },
                model_version=self.version
            )

        return None
