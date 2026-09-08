import os
import time
from typing import Generator, Optional
from ingest.models import PacketMetadata

class PCAPReader:
    """
    Incremental generator reader for PCAP files.
    Extracts packet metadata passively without inspecting payload contents.
    """

    def __init__(self, pcap_path: Optional[str] = None):
        self.pcap_path = pcap_path
        self._scapy_available = False
        try:
            from scapy.all import PcapReader as ScapyPcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR
            self._scapy_available = True
        except ImportError:
            self._scapy_available = False

    def read_packets(self, speed_multiplier: float = 1.0) -> Generator[PacketMetadata, None, None]:
        """
        Iterates over PCAP packets incrementally.
        Optionally delays emission to match original or accelerated timestamps.
        """
        if not self.pcap_path or not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        from scapy.all import PcapReader as ScapyPcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR

        last_pkt_time: Optional[float] = None
        last_wall_time: Optional[float] = None

        with ScapyPcapReader(self.pcap_path) as reader:
            for scapy_pkt in reader:
                meta = self._parse_scapy_packet(scapy_pkt)
                if meta is None:
                    continue

                if speed_multiplier > 0 and last_pkt_time is not None and last_wall_time is not None:
                    pkt_delta = (meta.timestamp - last_pkt_time) / speed_multiplier
                    if pkt_delta > 0:
                        wall_delta = time.time() - last_wall_time
                        sleep_time = pkt_delta - wall_delta
                        if 0 < sleep_time < 2.0:
                            time.sleep(sleep_time)

                last_pkt_time = meta.timestamp
                last_wall_time = time.time()
                yield meta

    def _parse_scapy_packet(self, scapy_pkt) -> Optional[PacketMetadata]:
        from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR

        pkt_time = float(scapy_pkt.time)
        pkt_len = len(scapy_pkt)

        src_ip, dst_ip = None, None
        if scapy_pkt.haslayer(IP):
            src_ip = scapy_pkt[IP].src
            dst_ip = scapy_pkt[IP].dst
        elif scapy_pkt.haslayer(IPv6):
            src_ip = scapy_pkt[IPv6].src
            dst_ip = scapy_pkt[IPv6].dst
        else:
            return None  # Non-IP packet

        src_port, dst_port = 0, 0
        protocol = "IP"
        tcp_flags = None

        if scapy_pkt.haslayer(TCP):
            src_port = scapy_pkt[TCP].sport
            dst_port = scapy_pkt[TCP].dport
            protocol = "TCP"
            tcp_flags = int(scapy_pkt[TCP].flags)
        elif scapy_pkt.haslayer(UDP):
            src_port = scapy_pkt[UDP].sport
            dst_port = scapy_pkt[UDP].dport
            protocol = "UDP"

        # Application metadata extraction
        dns_query = None
        dns_type = None
        if scapy_pkt.haslayer(DNS) and scapy_pkt.haslayer(DNSQR):
            try:
                qname = scapy_pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                dns_query = qname
                dns_type = str(scapy_pkt[DNSQR].qtype)
            except Exception:
                pass

        tls_sni = None
        tls_version = None
        # Basic TLS ClientHello SNI extraction heuristic if unencrypted
        if protocol == "TCP" and (src_port == 443 or dst_port == 443) and scapy_pkt.haslayer(TCP):
            payload = bytes(scapy_pkt[TCP].payload)
            if payload and len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                tls_sni = self._extract_sni_from_payload(payload)
                tls_version = "TLS 1.2/1.3"

        return PacketMetadata(
            timestamp=pkt_time,
            length=pkt_len,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            tcp_flags=tcp_flags,
            dns_query=dns_query,
            dns_type=dns_type,
            tls_sni=tls_sni,
            tls_version=tls_version,
            raw_payload_len=len(scapy_pkt[TCP].payload) if scapy_pkt.haslayer(TCP) else 0
        )

    def _extract_sni_from_payload(self, payload: bytes) -> Optional[str]:
        try:
            # Simple parse for SNI extension (0x0000) in TLS ClientHello payload
            pos = 5  # Skip TLS Record Header
            if pos >= len(payload) or payload[pos] != 0x01:  # Client Hello
                return None
            pos += 38  # Skip Handshake header, version, random, session_id
            if pos >= len(payload):
                return None
            session_id_len = payload[pos]
            pos += 1 + session_id_len
            if pos + 2 >= len(payload):
                return None
            cipher_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2 + cipher_len
            if pos >= len(payload):
                return None
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 >= len(payload):
                return None
            ext_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            end_ext = min(len(payload), pos + ext_len)

            while pos + 4 <= end_ext:
                ext_type = int.from_bytes(payload[pos:pos+2], 'big')
                ext_data_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                pos += 4
                if ext_type == 0:  # server_name extension
                    if pos + 5 <= end_ext:
                        list_len = int.from_bytes(payload[pos:pos+2], 'big')
                        name_type = payload[pos+2]
                        name_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                        if name_type == 0 and pos + 5 + name_len <= end_ext:
                            sni_bytes = payload[pos+5:pos+5+name_len]
                            return sni_bytes.decode('ascii', errors='ignore')
                pos += ext_data_len
        except Exception:
            pass
        return None
