import numpy as np
from typing import Dict, Any, Tuple, List
from flows.flow_key import Flow
from features.network_features import extract_network_features
from features.temporal_features import extract_temporal_features
from features.dns_features import extract_dns_features
from features.tls_features import extract_tls_features
from features.baseline_profiler import global_profiler

class FeaturePipeline:
    """Unified Feature Extraction Pipeline combining metadata and baseline features into standard dict and vector."""

    FEATURE_NAMES = [
        "duration", "total_packets", "total_bytes", "fwd_packets", "rev_packets",
        "fwd_bytes", "rev_bytes", "packets_per_sec", "bytes_per_sec", "mean_pkt_size",
        "std_pkt_size", "bytes_ratio", "outbound_asymmetry", "syn_ack_ratio",
        "mean_iat", "std_iat", "cov_iat", "periodicity_score", "burstiness",
        "dns_query_count", "max_dns_entropy", "max_query_length", "vowel_ratio", "digit_ratio",
        "sni_entropy", "sni_length", "byte_zscore", "packet_zscore"
    ]

    def __init__(self):
        self.profiler = global_profiler

    def extract_features(self, flow: Flow, is_attack: bool = False) -> Dict[str, Any]:
        net_feats = extract_network_features(flow)
        temp_feats = extract_temporal_features(flow)
        dns_feats = extract_dns_features(flow.dns_queries)
        tls_feats = extract_tls_features(flow.tls_snis, flow.tls_version)
        base_feats = self.profiler.get_baseline_features(flow.initiator_ip, flow.fwd_bytes, flow.fwd_packets, is_attack=is_attack)

        features = {}
        features.update(net_feats)
        features.update(temp_feats)
        features.update(dns_feats)
        features.update(tls_feats)
        features.update(base_feats)

        # Context identifiers
        features["flow_id"] = flow.flow_id
        features["initiator_ip"] = flow.initiator_ip
        features["responder_ip"] = flow.responder_ip
        features["initiator_port"] = flow.initiator_port
        features["responder_port"] = flow.responder_port
        features["protocol"] = flow.protocol

        return features

    def extract_vector(self, flow: Flow) -> np.ndarray:
        feats = self.extract_features(flow)
        vector = [float(feats.get(name, 0.0)) for name in self.FEATURE_NAMES]
        return np.array(vector, dtype=np.float32)
