import math
from collections import Counter
from typing import Dict, Any, List

def calculate_shannon_entropy(text: str) -> float:
    """Compute Shannon entropy for a given string."""
    if not text:
        return 0.0
    counts = Counter(text.lower())
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def extract_dns_features(dns_queries: List[str]) -> Dict[str, Any]:
    """Extract features from DNS queries associated with a flow or host."""
    if not dns_queries:
        return {
            "dns_query_count": 0,
            "max_dns_entropy": 0.0,
            "avg_dns_entropy": 0.0,
            "max_query_length": 0,
            "subdomain_count": 0,
            "vowel_ratio": 0.0,
            "digit_ratio": 0.0
        }

    entropies = [calculate_shannon_entropy(q) for q in dns_queries]
    lengths = [len(q) for q in dns_queries]

    primary_q = dns_queries[0].lower()
    vowels = set("aeiou")
    vowel_count = sum(1 for c in primary_q if c in vowels)
    digit_count = sum(1 for c in primary_q if c.isdigit())
    alpha_count = sum(1 for c in primary_q if c.isalpha())

    subdomains = primary_q.split('.')
    subdomain_count = len(subdomains) - 1 if len(subdomains) > 1 else 0

    return {
        "dns_query_count": len(dns_queries),
        "max_dns_entropy": float(max(entropies)),
        "avg_dns_entropy": float(sum(entropies) / len(entropies)),
        "max_query_length": max(lengths),
        "subdomain_count": subdomain_count,
        "vowel_ratio": vowel_count / (len(primary_q) + 1e-6),
        "digit_ratio": digit_count / (len(primary_q) + 1e-6)
    }
