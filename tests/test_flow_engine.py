import time
import pytest
from ingest.models import PacketMetadata
from flows.flow_key import CanonicalFlowKey, Flow
from flows.flow_manager import FlowManager

def test_canonical_flow_key():
    pkt1 = PacketMetadata(
        timestamp=100.0, length=64, src_ip="10.0.0.1", dst_ip="192.168.1.1",
        src_port=49152, dst_port=80, protocol="TCP"
    )
    pkt2 = PacketMetadata(
        timestamp=100.1, length=120, src_ip="192.168.1.1", dst_ip="10.0.0.1",
        src_port=80, dst_port=49152, protocol="TCP"
    )

    key1 = CanonicalFlowKey.from_packet(pkt1)
    key2 = CanonicalFlowKey.from_packet(pkt2)

    # Canonical keys MUST match regardless of direction
    assert key1 == key2

def test_flow_direction_tracking():
    pkt_fwd = PacketMetadata(
        timestamp=100.0, length=64, src_ip="10.0.0.1", dst_ip="192.168.1.1",
        src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02  # SYN
    )
    pkt_rev = PacketMetadata(
        timestamp=100.05, length=64, src_ip="192.168.1.1", dst_ip="10.0.0.1",
        src_port=80, dst_port=49152, protocol="TCP", tcp_flags=0x12  # SYN-ACK
    )

    key = CanonicalFlowKey.from_packet(pkt_fwd)
    flow = Flow(key, pkt_fwd)

    assert flow.initiator_ip == "10.0.0.1"
    assert flow.responder_ip == "192.168.1.1"
    assert flow.fwd_packets == 1
    assert flow.rev_packets == 0
    assert flow.fwd_syn == 1

    # Add reverse packet
    flow.add_packet(pkt_rev)
    assert flow.fwd_packets == 1
    assert flow.rev_packets == 1
    assert flow.rev_syn_ack == 1
    assert flow.total_packets == 2
    assert flow.total_bytes == 128
    assert len(flow.all_iats) == 1
    assert pytest.approx(flow.all_iats[0], 0.001) == 0.05

def test_flow_manager_sliding_window():
    fm = FlowManager(active_timeout_seconds=10.0, idle_timeout_seconds=5.0, window_seconds=2.0)

    # Emulate packets over time
    pkt1 = PacketMetadata(timestamp=1.0, length=100, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=5000, dst_port=53, protocol="UDP")
    pkt2 = PacketMetadata(timestamp=3.5, length=150, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=5000, dst_port=53, protocol="UDP")

    emitted1 = fm.process_packet(pkt1)
    assert len(emitted1) == 0

    # Delta = 3.5 - 1.0 = 2.5s >= 2.0s window -> emits active flow snapshot
    emitted2 = fm.process_packet(pkt2)
    assert len(emitted2) == 1
    assert emitted2[0].total_packets == 2
