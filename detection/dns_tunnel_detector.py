from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult

class DNSTunnelDetector(BaseDetector):
    """
    DNS Covert Tunneling Detector.
    Identifies high-volume, high-entropy subdomain payloads transmitted over DNS queries.
    """

    def __init__(self, query_len_thresh: int = 40, entropy_thresh: float = 3.8):
        super().__init__(name="DNSTunnelDetector", version="dns-tunnel-v1.0")
        self.query_len_thresh = query_len_thresh
        self.entropy_thresh = entropy_thresh

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        dns_count = flow_features.get("dns_query_count", 0)
        if dns_count == 0:
            return None

        max_len = flow_features.get("max_query_length", 0)
        entropy = flow_features.get("max_dns_entropy", 0.0)
        subdomain_count = flow_features.get("subdomain_count", 0)

        if max_len >= self.query_len_thresh and entropy >= self.entropy_thresh and subdomain_count >= 2:
            confidence = min(0.96, 0.70 + (max_len / 100.0) * 0.25)
            return DetectionResult(
                threat_class="DNS_TUNNELING",
                detected=True,
                confidence=round(confidence, 2),
                severity="CRITICAL",
                evidence={
                    "max_query_length": max_len,
                    "subdomain_entropy": round(entropy, 2),
                    "subdomain_depth": subdomain_count
                },
                contributing_features={
                    "query_length": 0.45,
                    "subdomain_entropy": 0.35,
                    "subdomain_depth": 0.20
                },
                model_version=self.version
            )

        return None
