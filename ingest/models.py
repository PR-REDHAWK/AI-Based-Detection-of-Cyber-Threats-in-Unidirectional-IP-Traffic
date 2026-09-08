from dataclasses import dataclass, field
from typing import Optional, Dict, Any

@dataclass
class PacketMetadata:
    """Passively extracted packet metadata without payload decryption."""
    timestamp: float
    length: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, etc.
    tcp_flags: Optional[int] = None  # Bitmask (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08, URG=0x20)
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher_suites: Optional[list] = None
    raw_payload_len: int = 0
