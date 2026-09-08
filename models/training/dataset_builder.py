import numpy as np
import pandas as pd
from typing import Tuple
from features.feature_pipeline import FeaturePipeline

class DatasetBuilder:
    """
    Realistic synthetic dataset builder for Machine Learning threat classifiers.
    Introduces realistic variance, jitter, and overlapping feature bounds across classes
    to eliminate artificial 100% metrics while evaluating classification performance.
    """

    def __init__(self):
        self.pipeline = FeaturePipeline()

    def generate_synthetic_dataset(self, samples_per_class: int = 300) -> pd.DataFrame:
        """Synthesizes realistic feature vectors with statistical overlap across all target classes."""
        data = []
        feature_names = self.pipeline.FEATURE_NAMES
        np.random.seed(42)

        # 0: BENIGN
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["duration"] = max(0.1, float(np.random.normal(loc=5.0, scale=3.0)))
            row["periodicity_score"] = float(np.clip(np.random.normal(loc=0.35, scale=0.15), 0.05, 0.75))
            row["max_dns_entropy"] = float(np.clip(np.random.normal(loc=2.5, scale=0.8), 1.0, 4.2))
            row["bytes_ratio"] = float(np.clip(np.random.normal(loc=1.0, scale=0.6), 0.1, 4.0))
            row["fwd_syn"] = float(np.random.randint(1, 10))
            row["syn_ack_ratio"] = float(np.clip(np.random.normal(loc=0.9, scale=0.1), 0.5, 1.0))
            row["packets_per_sec"] = float(np.clip(np.random.normal(loc=15.0, scale=10.0), 1.0, 60.0))
            row["session_group"] = f"session_benign_{session_id // 5}"
            row["class_id"] = 0
            row["label"] = "BENIGN"
            data.append(row)

        # 1: SYN_FLOOD (High SYN rate, low SYN-ACK completion, with bursty overlap)
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["duration"] = float(np.clip(np.random.normal(loc=2.0, scale=1.0), 0.1, 10.0))
            row["fwd_syn"] = float(np.clip(np.random.normal(loc=150.0, scale=60.0), 40.0, 400.0))
            row["syn_ack_ratio"] = float(np.clip(np.random.normal(loc=0.08, scale=0.06), 0.0, 0.25))
            row["packets_per_sec"] = float(np.clip(np.random.normal(loc=250.0, scale=100.0), 45.0, 800.0))
            row["session_group"] = f"session_syn_{session_id // 5}"
            row["class_id"] = 1
            row["label"] = "SYN_FLOOD"
            data.append(row)

        # 2: C2_BEACONING (High periodicity with jitter)
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["periodicity_score"] = float(np.clip(np.random.normal(loc=0.88, scale=0.08), 0.65, 0.99))
            row["std_iat"] = float(np.clip(np.random.normal(loc=0.4, scale=0.3), 0.01, 1.8))
            row["mean_iat"] = float(np.clip(np.random.normal(loc=15.0, scale=8.0), 2.0, 45.0))
            row["session_group"] = f"session_c2_{session_id // 5}"
            row["class_id"] = 2
            row["label"] = "C2_BEACONING"
            data.append(row)

        # 3: DGA_DOMAIN (Elevated entropy, digit ratio, low vowel ratio)
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["max_dns_entropy"] = float(np.clip(np.random.normal(loc=4.1, scale=0.4), 3.2, 5.0))
            row["digit_ratio"] = float(np.clip(np.random.normal(loc=0.30, scale=0.10), 0.15, 0.55))
            row["vowel_ratio"] = float(np.clip(np.random.normal(loc=0.14, scale=0.06), 0.02, 0.28))
            row["dns_query_count"] = float(np.random.randint(2, 20))
            row["session_group"] = f"session_dga_{session_id // 5}"
            row["class_id"] = 3
            row["label"] = "DGA_DOMAIN"
            data.append(row)

        # 4: EXFILTRATION (High outbound volume & ratio with backup overlap)
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["fwd_bytes"] = float(np.clip(np.random.normal(loc=5e6, scale=3e6), 5e5, 3e7))
            row["bytes_ratio"] = float(np.clip(np.random.normal(loc=8.0, scale=4.0), 2.5, 25.0))
            row["byte_zscore"] = float(np.clip(np.random.normal(loc=4.5, scale=2.0), 1.5, 10.0))
            row["session_group"] = f"session_exfil_{session_id // 5}"
            row["class_id"] = 4
            row["label"] = "EXFILTRATION"
            data.append(row)

        # 5: PORT_SCAN (Sequential port attempts, short duration)
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["packets_per_sec"] = float(np.clip(np.random.normal(loc=80.0, scale=30.0), 20.0, 200.0))
            row["duration"] = float(np.clip(np.random.normal(loc=1.5, scale=0.8), 0.1, 4.0))
            row["fwd_packets"] = float(np.random.randint(15, 60))
            row["session_group"] = f"session_scan_{session_id // 5}"
            row["class_id"] = 5
            row["label"] = "PORT_SCAN"
            data.append(row)

        # 6: DNS_TUNNELING (Very long query length & high subdomain entropy)
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["max_query_length"] = float(np.clip(np.random.normal(loc=55.0, scale=12.0), 35.0, 95.0))
            row["max_dns_entropy"] = float(np.clip(np.random.normal(loc=4.3, scale=0.4), 3.5, 5.2))
            row["dns_query_count"] = float(np.random.randint(10, 50))
            row["session_group"] = f"session_dnstunnel_{session_id // 5}"
            row["class_id"] = 6
            row["label"] = "DNS_TUNNELING"
            data.append(row)

        # 7: UDP_AMPLIFICATION (High UDP packet rate & asymmetric byte ratio)
        for session_id in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.5)) for name in feature_names}
            row["packets_per_sec"] = float(np.clip(np.random.normal(loc=350.0, scale=120.0), 90.0, 900.0))
            row["bytes_ratio"] = float(np.clip(np.random.normal(loc=12.0, scale=5.0), 3.5, 35.0))
            row["session_group"] = f"session_udpamp_{session_id // 5}"
            row["class_id"] = 7
            row["label"] = "UDP_AMPLIFICATION"
            data.append(row)

        return pd.DataFrame(data)
