import math
from typing import Dict, Any, Tuple
from flows.flow_key import Flow

class HostBaselineProfiler:
    """
    Rolling Statistical Baseline & Behavior Profiler per host/service.
    Calculates rolling mean and standard deviation of connection rates, byte volumes,
    and computes Z-score statistical deviations for anomaly and exfiltration detection.
    """

    def __init__(self, alpha: float = 0.1):
        self.alpha = alpha  # Exponential moving average decay parameter
        # host_ip -> { "mean_bytes": float, "std_bytes": float, "mean_pkts": float, "count": int }
        self.host_profiles: Dict[str, Dict[str, float]] = {}

    def update_and_get_deviation(self, flow: Flow, flow_features: Dict[str, Any]) -> Dict[str, float]:
        host_ip = flow.initiator_ip
        bytes_sent = float(flow.fwd_bytes)
        pkts_sent = float(flow.fwd_packets)

        if host_ip not in self.host_profiles:
            self.host_profiles[host_ip] = {
                "mean_bytes": bytes_sent,
                "std_bytes": 100.0,
                "mean_pkts": pkts_sent,
                "std_pkts": 5.0,
                "count": 1
            }
            return {"byte_zscore": 0.0, "pkt_zscore": 0.0, "is_new_host": 1.0}

        profile = self.host_profiles[host_ip]

        # Calculate Z-scores prior to updating baseline
        bytes_diff = abs(bytes_sent - profile["mean_bytes"])
        byte_zscore = bytes_diff / max(profile["std_bytes"], 10.0)

        pkts_diff = abs(pkts_sent - profile["mean_pkts"])
        pkt_zscore = pkts_diff / max(profile["std_pkts"], 1.0)

        # Update EMA baseline metrics
        profile["mean_bytes"] = (1 - self.alpha) * profile["mean_bytes"] + self.alpha * bytes_sent
        profile["std_bytes"] = (1 - self.alpha) * profile["std_bytes"] + self.alpha * bytes_diff

        profile["mean_pkts"] = (1 - self.alpha) * profile["mean_pkts"] + self.alpha * pkts_sent
        profile["std_pkts"] = (1 - self.alpha) * profile["std_pkts"] + self.alpha * pkts_diff

        profile["count"] += 1

        return {
            "byte_zscore": round(byte_zscore, 2),
            "pkt_zscore": round(pkt_zscore, 2),
            "is_new_host": 0.0
        }
