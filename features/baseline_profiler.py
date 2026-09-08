import math
from typing import Dict, Any

class HostBaselineProfiler:
    """
    Rolling Statistical Baseline & Behavior Profiler per host.
    Tracks exponential moving average (EMA) of forward bytes and packets,
    computing Z-scores while enforcing cold-start and attack protection policies.
    """

    def __init__(self, alpha: float = 0.1, min_history_flows: int = 3):
        self.alpha = alpha
        self.min_history_flows = min_history_flows
        # host_ip -> { "mean_bytes": float, "std_bytes": float, "mean_pkts": float, "std_pkts": float, "flow_count": int }
        self.host_profiles: Dict[str, Dict[str, Any]] = {}

    def get_baseline_features(self, initiator_ip: str, fwd_bytes: int, fwd_pkts: int, is_attack: bool = False) -> Dict[str, float]:
        bytes_val = float(fwd_bytes)
        pkts_val = float(fwd_pkts)

        if initiator_ip not in self.host_profiles:
            self.host_profiles[initiator_ip] = {
                "mean_bytes": bytes_val,
                "std_bytes": 100.0,
                "mean_pkts": pkts_val,
                "std_pkts": 5.0,
                "flow_count": 1
            }
            # Cold-start policy: Return neutral Z-scores for new hosts
            return {
                "byte_zscore": 0.0,
                "packet_zscore": 0.0,
                "host_flow_count": 1.0
            }

        profile = self.host_profiles[initiator_ip]
        flow_count = profile["flow_count"]

        # Cold start check
        if flow_count < self.min_history_flows:
            byte_zscore = 0.0
            packet_zscore = 0.0
        else:
            bytes_diff = abs(bytes_val - profile["mean_bytes"])
            byte_zscore = bytes_diff / max(profile["std_bytes"], 10.0)

            pkts_diff = abs(pkts_val - profile["mean_pkts"])
            packet_zscore = pkts_diff / max(profile["std_pkts"], 1.0)

        # Attack Protection Policy: Do not contaminate baseline with attack traffic
        if not is_attack:
            bytes_diff = abs(bytes_val - profile["mean_bytes"])
            pkts_diff = abs(pkts_val - profile["mean_pkts"])

            profile["mean_bytes"] = (1 - self.alpha) * profile["mean_bytes"] + self.alpha * bytes_val
            profile["std_bytes"] = (1 - self.alpha) * profile["std_bytes"] + self.alpha * bytes_diff

            profile["mean_pkts"] = (1 - self.alpha) * profile["mean_pkts"] + self.alpha * pkts_val
            profile["std_pkts"] = (1 - self.alpha) * profile["std_pkts"] + self.alpha * pkts_diff

            profile["flow_count"] += 1

        return {
            "byte_zscore": round(float(byte_zscore), 2),
            "packet_zscore": round(float(packet_zscore), 2),
            "host_flow_count": float(profile["flow_count"])
        }

global_profiler = HostBaselineProfiler()
