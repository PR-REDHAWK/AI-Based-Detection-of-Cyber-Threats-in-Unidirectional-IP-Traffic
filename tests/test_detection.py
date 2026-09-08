import pytest
from flows.flow_key import CanonicalFlowKey, Flow
from ingest.models import PacketMetadata
from features.feature_pipeline import FeaturePipeline
from detection.ensemble import RiskEngine

def test_syn_flood_detection():
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    pkt_syn = PacketMetadata(
        timestamp=100.0, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10",
        src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02  # SYN only
    )
    key = CanonicalFlowKey.from_packet(pkt_syn)
    flow = Flow(key, pkt_syn)

    # Add 100 SYN packets quickly to simulate a SYN flood in a single flow
    for i in range(1, 100):
        flow.add_packet(PacketMetadata(
            timestamp=100.0 + i*0.01, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10",
            src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02
        ))

    feats = pipeline.extract_features(flow)
    alert = engine.analyze(flow, feats)

    assert alert is not None
    assert alert.threat_class == "SYN_FLOOD"
    assert alert.severity == "CRITICAL"
    assert alert.confidence >= 0.70
    assert "syn_rate_per_sec" in alert.evidence

def test_beacon_c2_detection():
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    # Simulate regular periodic packets every 10 seconds
    pkt0 = PacketMetadata(timestamp=0.0, length=100, src_ip="10.0.0.10", dst_ip="198.51.100.4", src_port=52000, dst_port=443, protocol="TCP")
    key = CanonicalFlowKey.from_packet(pkt0)
    flow = Flow(key, pkt0)

    for step in range(1, 10):
        flow.add_packet(PacketMetadata(
            timestamp=step * 10.0, length=100, src_ip="10.0.0.10", dst_ip="198.51.100.4",
            src_port=52000, dst_port=443, protocol="TCP"
        ))

    feats = pipeline.extract_features(flow)
    alert = engine.analyze(flow, feats)

    assert alert is not None
    assert alert.threat_class == "C2_BEACONING"
    assert alert.severity == "HIGH"
    assert alert.evidence["periodicity_score"] > 0.85
