import time
import random
from typing import List
from ingest.models import PacketMetadata

class TrafficGenerator:
    """
    Synthetic Traffic Generator producing both benign baseline traffic
    and controlled local attack traffic for all required SIH threat classes.
    """

    BENIGN_HOSTS = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "10.0.4.5"]
    EXTERNAL_SERVICES = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "142.250.190.46"]

    def generate_benign_flow(self, timestamp: float) -> List[PacketMetadata]:
        """Synthesizes a normal HTTP/DNS packet sequence."""
        src_ip = random.choice(self.BENIGN_HOSTS)
        dst_ip = random.choice(self.EXTERNAL_SERVICES)
        src_port = random.randint(49152, 65535)
        dst_port = 443 if random.random() > 0.3 else 80

        return [
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

    def generate_syn_flood(self, timestamp: float, duration_seconds: float = 3.0, rate: float = 60.0) -> List[PacketMetadata]:
        """Synthesizes a high-rate SYN flood targeting a local server."""
        src_ip = "10.20.4.15"
        dst_ip = "192.168.1.10"
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

    def generate_udp_amplification(self, timestamp: float, rate: float = 120.0) -> List[PacketMetadata]:
        """Synthesizes a UDP amplification burst with high asymmetric payload volume."""
        src_ip = "198.51.100.77"
        dst_ip = "192.168.1.10"
        packets = []
        t = timestamp

        for _ in range(30):
            packets.append(PacketMetadata(
                timestamp=t, length=1420, src_ip=src_ip, dst_ip=dst_ip,
                src_port=123, dst_port=55100, protocol="UDP"
            ))
            t += 1.0 / rate

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

    def generate_host_scan(self, timestamp: float, host_count: int = 20) -> List[PacketMetadata]:
        """Synthesizes a horizontal host scan across subnet IPs."""
        src_ip = "172.16.0.44"
        packets = []
        t = timestamp

        for h in range(1, host_count + 1):
            dst_ip = f"192.168.1.{10 + h}"
            packets.append(PacketMetadata(
                timestamp=t, length=64, src_ip=src_ip, dst_ip=dst_ip,
                src_port=55000, dst_port=445, protocol="TCP", tcp_flags=0x02
            ))
            t += 0.05

        return packets

    def generate_c2_beacon(self, timestamp: float, count: int = 8, interval: float = 2.0) -> List[PacketMetadata]:
        """Synthesizes a regular periodic C2 beacon flow."""
        src_ip = "192.168.1.20"
        c2_ip = "198.51.100.99"
        packets = []
        t = timestamp

        for i in range(count):
            packets.append(PacketMetadata(
                timestamp=t, length=128, src_ip=src_ip, dst_ip=c2_ip,
                src_port=49999, dst_port=443, protocol="TCP", tls_sni="c2-cmd-node.org"
            ))
            t += interval

        return packets

    def generate_dga_traffic(self, timestamp: float) -> List[PacketMetadata]:
        """Synthesizes DGA DNS query traffic with high entropy labels."""
        src_ip = "192.168.1.15"
        dns_server = "8.8.8.8"
        dga_domain = "x7z9qkw912mzbv0q81l.biz"
        
        return [
            PacketMetadata(
                timestamp=timestamp, length=110, src_ip=src_ip, dst_ip=dns_server,
                src_port=54000, dst_port=53, protocol="UDP", dns_query=dga_domain, dns_type="1"
            )
        ]

    def generate_dns_tunneling(self, timestamp: float) -> List[PacketMetadata]:
        """Synthesizes DNS covert tunneling traffic with long encoded subdomains."""
        src_ip = "192.168.1.15"
        dns_server = "8.8.8.8"
        tunnel_domain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.covert-tunnel.org"

        return [
            PacketMetadata(
                timestamp=timestamp, length=180, src_ip=src_ip, dst_ip=dns_server,
                src_port=54001, dst_port=53, protocol="UDP", dns_query=tunnel_domain, dns_type="16"
            )
        ]

    def generate_exfiltration(self, timestamp: float) -> List[PacketMetadata]:
        """Synthesizes large outbound data exfiltration transfer."""
        src_ip = "192.168.1.10"
        c2_exfil_ip = "203.0.113.88"
        packets = []
        t = timestamp

        for i in range(40):
            packets.append(PacketMetadata(
                timestamp=t, length=1460, src_ip=src_ip, dst_ip=c2_exfil_ip,
                src_port=49500, dst_port=443, protocol="TCP"
            ))
            t += 0.01

        return packets

    def generate_encrypted_session_anomaly(self, timestamp: float) -> List[PacketMetadata]:
        """Synthesizes suspicious TLS metadata session with anomalous SNI and timing."""
        src_ip = "192.168.1.15"
        dst_ip = "198.51.100.222"
        suspicious_sni = "xzk9012-encrypted-c2-channel.net"
        packets = []
        t = timestamp

        for i in range(10):
            packets.append(PacketMetadata(
                timestamp=t, length=1200, src_ip=src_ip, dst_ip=dst_ip,
                src_port=51100, dst_port=443, protocol="TCP", tls_sni=suspicious_sni, tls_version="TLS 1.3"
            ))
            t += 0.2

        return packets
