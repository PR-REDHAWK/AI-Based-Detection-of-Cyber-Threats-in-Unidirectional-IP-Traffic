from dataclasses import dataclass, field
from typing import Tuple, List, Optional
from ingest.models import PacketMetadata

@dataclass(frozen=True)
class CanonicalFlowKey:
    """Canonical bidirectional 5-tuple key for flow aggregation."""
    ep1_ip: str
    ep1_port: int
    ep2_ip: str
    ep2_port: int
    protocol: str

    @classmethod
    def from_packet(cls, pkt: PacketMetadata) -> "CanonicalFlowKey":
        """Build canonical key where lower endpoint tuple comes first."""
        ep_a = (pkt.src_ip, pkt.src_port)
        ep_b = (pkt.dst_ip, pkt.dst_port)
        if ep_a <= ep_b:
            return cls(ep_a[0], ep_a[1], ep_b[0], ep_b[1], pkt.protocol.upper())
        else:
            return cls(ep_b[0], ep_b[1], ep_a[0], ep_a[1], pkt.protocol.upper())

    def to_string(self) -> str:
        return f"{self.ep1_ip}:{self.ep1_port}<->{self.ep2_ip}:{self.ep2_port}/{self.protocol}"


class Flow:
    """
    Bidirectional network flow tracking state incrementally.
    Preserves original directionality (Initiator vs Responder).
    """

    def __init__(self, key: CanonicalFlowKey, initial_packet: PacketMetadata):
        self.key = key
        self.flow_id = f"FLOW-{abs(hash(key.to_string())) % 1000000:06d}"
        
        # Initiator is the source of the first observed packet
        self.initiator_ip = initial_packet.src_ip
        self.initiator_port = initial_packet.src_port
        self.responder_ip = initial_packet.dst_ip
        self.responder_port = initial_packet.dst_port
        self.protocol = initial_packet.protocol.upper()

        self.first_seen = initial_packet.timestamp
        self.last_seen = initial_packet.timestamp

        # Counters
        self.fwd_packets = 0
        self.rev_packets = 0
        self.fwd_bytes = 0
        self.rev_bytes = 0

        # TCP Flag Counters (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08, URG=0x20)
        self.fwd_syn = 0
        self.rev_syn = 0
        self.fwd_syn_ack = 0
        self.rev_syn_ack = 0
        self.fwd_fin = 0
        self.rev_fin = 0
        self.fwd_rst = 0
        self.rev_rst = 0

        # Dynamics & Sequences
        self.packet_sizes: List[int] = []
        self.packet_directions: List[str] = []  # 'FWD' or 'REV'
        self.timestamps: List[float] = []
        self.all_iats: List[float] = []
        self.fwd_iats: List[float] = []
        self.rev_iats: List[float] = []

        # Application Metadata
        self.dns_queries: List[str] = []
        self.tls_snis: List[str] = []
        self.tls_version: Optional[str] = None

        # Add initial packet
        self.add_packet(initial_packet)

    def add_packet(self, pkt: PacketMetadata):
        """Update flow state with a new packet in real-time."""
        is_fwd = (pkt.src_ip == self.initiator_ip and pkt.src_port == self.initiator_port)

        # Update timing & inter-arrival times
        if self.timestamps:
            iat = max(0.0, pkt.timestamp - self.last_seen)
            self.all_iats.append(iat)
            if is_fwd:
                self.fwd_iats.append(iat)
            else:
                self.rev_iats.append(iat)

        self.last_seen = max(self.last_seen, pkt.timestamp)
        self.timestamps.append(pkt.timestamp)
        self.packet_sizes.append(pkt.length)

        if is_fwd:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.length
            self.packet_directions.append('FWD')
            if pkt.tcp_flags is not None:
                if (pkt.tcp_flags & 0x02) and not (pkt.tcp_flags & 0x10):
                    self.fwd_syn += 1
                elif (pkt.tcp_flags & 0x02) and (pkt.tcp_flags & 0x10):
                    self.fwd_syn_ack += 1
                if pkt.tcp_flags & 0x01:
                    self.fwd_fin += 1
                if pkt.tcp_flags & 0x04:
                    self.fwd_rst += 1
        else:
            self.rev_packets += 1
            self.rev_bytes += pkt.length
            self.packet_directions.append('REV')
            if pkt.tcp_flags is not None:
                if (pkt.tcp_flags & 0x02) and not (pkt.tcp_flags & 0x10):
                    self.rev_syn += 1
                elif (pkt.tcp_flags & 0x02) and (pkt.tcp_flags & 0x10):
                    self.rev_syn_ack += 1
                if pkt.tcp_flags & 0x01:
                    self.rev_fin += 1
                if pkt.tcp_flags & 0x04:
                    self.rev_rst += 1

        # Collect application metadata if present
        if pkt.dns_query and pkt.dns_query not in self.dns_queries:
            self.dns_queries.append(pkt.dns_query)
        if pkt.tls_sni and pkt.tls_sni not in self.tls_snis:
            self.tls_snis.append(pkt.tls_sni)
        if pkt.tls_version and not self.tls_version:
            self.tls_version = pkt.tls_version

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.rev_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.rev_bytes
