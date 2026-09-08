from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult

class DGADetector(BaseDetector):
    """
    Domain Generation Algorithm (DGA) Detector.
    Analyzes DNS query entropy, length, digit ratio, and character statistics to detect DGA domains.
    """

    def __init__(self, entropy_thresh: float = 3.6, digit_ratio_thresh: float = 0.25):
        super().__init__(name="DGADetector", version="dga-classifier-v1.0")
        self.entropy_thresh = entropy_thresh
        self.digit_ratio_thresh = digit_ratio_thresh

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        dns_count = flow_features.get("dns_query_count", 0)
        if dns_count == 0:
            return None

        max_entropy = flow_features.get("max_dns_entropy", 0.0)
        max_len = flow_features.get("max_query_length", 0)
        digit_ratio = flow_features.get("digit_ratio", 0.0)
        vowel_ratio = flow_features.get("vowel_ratio", 0.3)

        # High entropy + unusual length + high digit/consonant ratio -> High probability DGA
        if max_entropy >= self.entropy_thresh and (digit_ratio >= self.digit_ratio_thresh or vowel_ratio < 0.15):
            confidence = min(0.97, 0.65 + (max_entropy / 5.0) * 0.30)
            return DetectionResult(
                threat_class="DGA_DOMAIN",
                detected=True,
                confidence=round(confidence, 2),
                severity="HIGH",
                evidence={
                    "dns_entropy": round(max_entropy, 2),
                    "query_length": max_len,
                    "digit_ratio": round(digit_ratio, 2),
                    "vowel_ratio": round(vowel_ratio, 2)
                },
                contributing_features={
                    "shannon_entropy": 0.50,
                    "digit_ratio": 0.30,
                    "vowel_ratio": 0.20
                },
                model_version=self.version
            )

        return None
