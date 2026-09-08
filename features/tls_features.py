from typing import Dict, Any, List
from features.dns_features import calculate_shannon_entropy

def extract_tls_features(tls_snis: List[str], tls_version: str = None) -> Dict[str, Any]:
    """Extract metadata features from TLS sessions without payload decryption."""
    if not tls_snis:
        return {
            "has_tls": False if not tls_version else True,
            "tls_sni_count": 0,
            "sni_name": "",
            "sni_length": 0,
            "sni_entropy": 0.0,
            "tls_version": tls_version or "Unknown"
        }

    sni = tls_snis[0]
    return {
        "has_tls": True,
        "tls_sni_count": len(tls_snis),
        "sni_name": sni,
        "sni_length": len(sni),
        "sni_entropy": calculate_shannon_entropy(sni),
        "tls_version": tls_version or "TLS 1.2/1.3"
    }
