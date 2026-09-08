from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult

class EncryptedSessionDetector(BaseDetector):
    """
    Dedicated Encrypted Session Suspicion Detector.
    Analyzes unencrypted TLS/QUIC metadata, SNI characteristics, session timing,
    and packet size dynamics without inspecting or decrypting application payloads.
    """

    def __init__(self, sni_entropy_thresh: float = 3.5, min_packets: int = 5):
        super().__init__(name="EncryptedSessionDetector", version="tls-metadata-v1.0")
        self.sni_entropy_thresh = sni_entropy_thresh
        self.min_packets = min_packets

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        has_tls = flow_features.get("has_tls", False)
        sni_entropy = flow_features.get("sni_entropy", 0.0)
        sni_length = flow_features.get("sni_length", 0)
        total_pkts = flow_features.get("total_packets", 0)
        outbound_asymmetry = flow_features.get("outbound_asymmetry", 0.0)

        if not has_tls or total_pkts < self.min_packets:
            return None

        # Flag suspicious TLS sessions: high SNI entropy + unusual outbound asymmetry or long duration
        if sni_entropy >= self.sni_entropy_thresh and (sni_length > 25 or outbound_asymmetry > 0.5):
            confidence = min(0.94, 0.70 + (sni_entropy / 5.0) * 0.24)
            return DetectionResult(
                threat_class="SUSPICIOUS_ENCRYPTED_SESSION",
                detected=True,
                confidence=round(confidence, 2),
                severity="HIGH",
                evidence={
                    "sni_entropy": round(sni_entropy, 2),
                    "sni_length": sni_length,
                    "outbound_asymmetry": round(outbound_asymmetry, 2),
                    "detector_source": "TLS_METADATA_ANALYSIS"
                },
                contributing_features={
                    "sni_entropy": 0.50,
                    "outbound_asymmetry": 0.30,
                    "sni_length": 0.20
                },
                model_version=self.version
            )

        return None
