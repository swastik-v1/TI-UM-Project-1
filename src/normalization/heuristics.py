"""Explainable heuristic signals (Shannon Entropy DGA detection & Subnet Clustering).

All heuristics are mathematical and 100% deterministic (No AI / Machine Learning).
"""

import ipaddress
import math
from typing import Any, Dict, List, Set, Tuple


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon Entropy H(X) in bits per character.

    Higher entropy indicates random/pseudo-random character generation (e.g. DGAs).
    """
    if not text:
        return 0.0

    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def analyze_dga_heuristics(domain: str) -> Dict[str, Any]:
    """Evaluates domain for Domain Generation Algorithm (DGA) traits.

    Checks:
    - Shannon entropy of the second-level label
    - Length of second-level label
    - Consonant-to-vowel ratio
    - Digit ratio
    """
    clean_domain = domain.lower().strip().rstrip(".")
    labels = clean_domain.split(".")
    if not labels or len(labels) < 2:
        return {"is_likely_dga": False, "entropy": 0.0, "reason": "insufficient_labels"}

    # Evaluate the primary registering label (e.g. "xzkqp91amvl" from "xzkqp91amvl.biz")
    target_label = labels[-2] if len(labels) >= 2 else labels[0]
    entropy = calculate_shannon_entropy(target_label)

    vowels = set("aeiou")
    digits = set("0123456789")
    consonants = set("bcdfghjklmnpqrstvwxyz")

    v_count = sum(1 for c in target_label if c in vowels)
    c_count = sum(1 for c in target_label if c in consonants)
    d_count = sum(1 for c in target_label if c in digits)
    total_letters = v_count + c_count

    consonant_ratio = (c_count / total_letters) if total_letters > 0 else 0.0
    digit_ratio = d_count / len(target_label) if len(target_label) > 0 else 0.0

    # Heuristic rules:
    # 1. High entropy (> 3.7) with decent length (>= 9)
    # 2. Extreme consonant concentration with high entropy
    # 3. High digit mixing with high entropy
    is_dga = False
    reasons = []

    if len(target_label) >= 9 and entropy >= 3.65:
        is_dga = True
        reasons.append(f"high_entropy({entropy})")

    if len(target_label) >= 8 and consonant_ratio >= 0.85 and entropy >= 3.3:
        is_dga = True
        reasons.append(f"consonant_clustering({consonant_ratio:.2f})")

    if len(target_label) >= 8 and digit_ratio >= 0.4 and entropy >= 3.4:
        is_dga = True
        reasons.append(f"high_digit_ratio({digit_ratio:.2f})")

    return {
        "is_likely_dga": is_dga,
        "target_label": target_label,
        "entropy": entropy,
        "consonant_ratio": round(consonant_ratio, 2),
        "digit_ratio": round(digit_ratio, 2),
        "reasons": reasons,
    }


def analyze_subnet_clustering(
    ip_list: List[str],
    min_cluster_size: int = 3,
    allow_private: bool = True,
) -> Dict[str, List[str]]:
    """Identifies IPv4 /24 subnet clusters hosting multiple malicious indicators.

    Returns:
        Mapping of subnet CIDR -> list of member IPs
    """
    subnets: Dict[str, List[str]] = {}
    for ip_str in ip_list:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address) and not ip_obj.is_loopback and not ip_obj.is_multicast:
                if not allow_private and ip_obj.is_private:
                    continue
                net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                net_str = str(net)
                if net_str not in subnets:
                    subnets[net_str] = []
                if ip_str not in subnets[net_str]:
                    subnets[net_str].append(ip_str)
        except ValueError:
            continue

    # Filter to clusters meeting threshold
    return {net: ips for net, ips in subnets.items() if len(ips) >= min_cluster_size}
