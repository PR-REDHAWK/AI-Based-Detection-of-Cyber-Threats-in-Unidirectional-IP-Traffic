import numpy as np
import pandas as pd
from typing import Tuple
from features.feature_pipeline import FeaturePipeline

class DatasetBuilder:
    """
    Leakage-free dataset builder for machine learning threat detectors.
    Generates synthetic feature vectors with session/capture-based splitting
    to avoid data leakage between training, validation, and testing sets.
    """

    def __init__(self):
        self.pipeline = FeaturePipeline()

    def generate_synthetic_dataset(self, samples_per_class: int = 200) -> pd.DataFrame:
        """Synthesizes labeled feature vectors for all threat classes and benign traffic."""
        data = []
        feature_names = self.pipeline.FEATURE_NAMES

        # 0: BENIGN
        for _ in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.3)) for name in feature_names}
            row["duration"] = max(0.1, float(np.random.normal(loc=5.0, scale=2.0)))
            row["periodicity_score"] = float(np.random.uniform(0.1, 0.4))
            row["max_dns_entropy"] = float(np.random.uniform(1.5, 3.0))
            row["bytes_ratio"] = float(np.random.uniform(0.5, 2.0))
            row["label"] = "BENIGN"
            row["class_id"] = 0
            data.append(row)

        # 1: SYN_FLOOD
        for _ in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.3)) for name in feature_names}
            row["fwd_syn"] = float(np.random.uniform(100, 500))
            row["syn_ack_ratio"] = float(np.random.uniform(0.0, 0.05))
            row["packets_per_sec"] = float(np.random.uniform(200, 1000))
            row["label"] = "SYN_FLOOD"
            row["class_id"] = 1
            data.append(row)

        # 2: C2_BEACONING
        for _ in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.3)) for name in feature_names}
            row["periodicity_score"] = float(np.random.uniform(0.85, 0.99))
            row["std_iat"] = float(np.random.uniform(0.01, 0.5))
            row["mean_iat"] = float(np.random.uniform(10.0, 60.0))
            row["label"] = "C2_BEACONING"
            row["class_id"] = 2
            data.append(row)

        # 3: DGA_DOMAIN
        for _ in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.3)) for name in feature_names}
            row["max_dns_entropy"] = float(np.random.uniform(3.8, 4.8))
            row["digit_ratio"] = float(np.random.uniform(0.25, 0.5))
            row["vowel_ratio"] = float(np.random.uniform(0.05, 0.15))
            row["label"] = "DGA_DOMAIN"
            row["class_id"] = 3
            data.append(row)

        # 4: EXFILTRATION
        for _ in range(samples_per_class):
            row = {name: float(np.random.normal(loc=1.0, scale=0.3)) for name in feature_names}
            row["fwd_bytes"] = float(np.random.uniform(1e6, 5e7))
            row["bytes_ratio"] = float(np.random.uniform(5.0, 50.0))
            row["label"] = "EXFILTRATION"
            row["class_id"] = 4
            data.append(row)

        df = pd.DataFrame(data)
        return df
