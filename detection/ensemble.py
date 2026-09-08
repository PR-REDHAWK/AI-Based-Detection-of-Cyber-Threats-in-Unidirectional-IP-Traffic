from typing import List, Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult
from detection.ddos_detector import DDoSDetector
from detection.scanning_detector import ScanningDetector
from detection.beacon_detector import BeaconDetector
from detection.dga_detector import DGADetector
from detection.dns_tunnel_detector import DNSTunnelDetector
from detection.exfiltration_detector import ExfiltrationDetector
from detection.anomaly_detector import AnomalyDetector
from alerts.generator import AlertGenerator
from alerts.schema import Alert
from flows.flow_key import Flow

class RiskEngine:
    """
    Central Ensemble Risk Engine.
    Executes all active threat detectors, resolves weighted threat classifications,
    separates confidence from severity, and returns final alerts.
    """

    def __init__(self):
        self.detectors: List[BaseDetector] = [
            DDoSDetector(),
            ScanningDetector(),
            BeaconDetector(),
            DGADetector(),
            DNSTunnelDetector(),
            ExfiltrationDetector(),
            AnomalyDetector()
        ]
        self.alert_generator = AlertGenerator()

    def register_detector(self, detector: BaseDetector):
        self.detectors.append(detector)

    def analyze(self, flow: Flow, flow_features: Dict[str, Any]) -> Optional[Alert]:
        results: List[DetectionResult] = []

        for detector in self.detectors:
            try:
                res = detector.analyze_flow(flow_features)
                if res and res.detected:
                    results.append(res)
            except Exception:
                pass

        if not results:
            return None

        # Sort results by severity priority and confidence
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        results.sort(key=lambda r: (severity_rank.get(r.severity, 0), r.confidence), reverse=True)

        top_result = results[0]

        # Generate alert
        return self.alert_generator.generate(flow, top_result)
