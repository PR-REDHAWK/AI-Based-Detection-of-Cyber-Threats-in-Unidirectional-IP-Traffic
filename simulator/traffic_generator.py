import time
import random
from typing import List, Generator
from ingest.models import PacketMetadata

class TrafficGenerator:
    """
    Synthetic Traffic Generator producing both benign baseline traffic
    and controlled local attack traffic for demonstrations.
    """

    BENIGN_HOSTS = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "10.0.4.5"]
    EXTERNAL_SERVICES = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "142.250.190.46"]

    def generate_benign_flow(self, timestamp: float) -> List[PacketMetadata]:
        """Synthesizes a normal HTTP/DNS packet sequence."""
        src_ip = random.choice(self.BENIGN_HOSTS)
        dst_ip = random.choice(self.EXTERNAL_SERVICES)
        src_port = random.randint(49152, 65535)
        dst_port = 443 if random.random() > 0.3 else 80

        packets = [
            PacketMetadata(
                timestamp=timestamp, length=64, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol="TCP", tcp_flags=0x02  # SYN
            ),
            PacketMetadata(
                timestamp=timestamp + 0.02, length=64, src_ip=dst_ip, dst_ip=src_ip,
                src_port=dst_port, dst_port=src_port, protocol="TCP", tcp_flags=0x12  # SYN-ACK
            ),
            PacketMetadata(
                timestamp=timestamp + 0.03, length=54, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol="TCP", tcp_flags=0x10  # ACK
            ),
            PacketMetadata(
                timestamp=timestamp + 0.05, length=random.randint(200, 1200), src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol="TCP", tls_sni="example.org" if dst_port == 443 else None
            )
        ]
        return packets

    def generate_syn_flood(self, timestamp: float, duration_seconds: float = 3.0, rate: float = 60.0) -> List[PacketMetadata]:
        """Synthesizes a high-rate SYN flood targeting a local server."""
        src_ip = "10.20.4.15"  # Attacker IP
        dst_ip = "192.168.1.10" # Target server
        packets = []
        step = 1.0 / rate
        t = timestamp

        while t < timestamp + duration_seconds:
            src_port = random.randint(1024, 65535)
            packets.append(PacketMetadata(
                timestamp=t, length=64, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=80, protocol="TCP", tcp_flags=0x02  # SYN
            ))
            t += step

        return packets

    def generate_port_scan(self, timestamp: float, port_count: int = 25) -> List[PacketMetadata]:
        """Synthesizes a vertical port scan from a single source IP."""
        src_ip = "172.16.0.44"
        dst_ip = "192.168.1.10"
        packets = []
        t = timestamp

        for p in range(1, port_count + 1):
            dst_port = 80 + p
            packets.append(PacketMetadata(
                timestamp=t, length=64, src_ip=src_ip, dst_ip=dst_ip,
                src_port=55000, dst_port=dst_port, protocol="TCP", tcp_flags=0x02
            ))
            t += 0.05

        return packets

    def generate_c2_beacon(self, timestamp: float, count: int = 8, interval: float = 2.0) -> List[PacketMetadata]:
        """Synthesizes a regular periodic C2 beacon flow."""
        src_ip = "192.168.1.20"  # Infected host
        c2_ip = "198.51.100.99"   # Malicious C2 server
        packets = []
        t = timestamp

        for i in range(count):
            packets.append(PacketMetadata(
                timestamp=t, length=128, src_ip=src_ip, dst_ip=c2_ip,
                src_port=49999, dst_port=443, protocol="TCP", tls_sni="c2-cmd-node.org"
            ))
            t += interval

        return packets
