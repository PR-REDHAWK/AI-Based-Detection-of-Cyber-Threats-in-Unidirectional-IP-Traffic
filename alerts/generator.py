import time
from typing import Dict, Optional, Tuple
from alerts.schema import Alert
from detection.base_detector import DetectionResult
from flows.flow_key import Flow

class AlertGenerator:
    """Generates standardized Alert models with deduplication logic."""

    def __init__(self, dedup_window_seconds: float = 10.0):
        self.dedup_window = dedup_window_seconds
        self.recent_alerts: Dict[Tuple[str, str, str], float] = {}  # (src_ip, dst_ip, threat_class) -> timestamp
        self.alert_counter = 0

    def generate(self, flow: Flow, result: DetectionResult) -> Optional[Alert]:
        now = time.time()
        dedup_key = (flow.initiator_ip, flow.responder_ip, result.threat_class)

        # Deduplication check
        if dedup_key in self.recent_alerts:
            last_time = self.recent_alerts[dedup_key]
            if (now - last_time) < self.dedup_window:
                return None  # Suppress duplicate alert

        self.recent_alerts[dedup_key] = now
        self.alert_counter += 1

        alert_id = f"ALT-2026-{self.alert_counter:06d}"

        return Alert(
            alert_id=alert_id,
            flow_id=flow.flow_id,
            src_ip=flow.initiator_ip,
            dst_ip=flow.responder_ip,
            src_port=flow.initiator_port,
            dst_port=flow.responder_port,
            protocol=flow.protocol,
            threat_class=result.threat_class,
            severity=result.severity,
            confidence=result.confidence,
            evidence=result.evidence,
            contributing_features=result.contributing_features,
            model_version=result.model_version
        )
