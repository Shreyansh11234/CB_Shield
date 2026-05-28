"""
threat_intel.py
---------------
Simulated VirusTotal-style threat intelligence lookup.

In production you would replace _vt_lookup_ip() with a real HTTP call:

    headers = {"x-apikey": os.getenv("VT_API_KEY")}
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
    data = r.json()
    malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

For now we simulate the response so the rest of the stack works without a key.
"""

import random


# Known-bad IPs (simulation only — these are placeholder values)
_KNOWN_BAD: set[str] = {
    "185.220.101.1",
    "198.51.100.42",
    "203.0.113.99",
}

# Private / loopback prefixes to skip
_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "::1", "fe80")


def is_public_ip(ip: str) -> bool:
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def check_ip(ip: str) -> dict:
    """
    Check an IP address against threat intelligence.

    Returns:
        {
            "malicious": bool,
            "risk_score": int,      # 0-100
            "vendor_flags": int,    # number of vendors that flagged it
            "detail": str
        }
    """
    if not is_public_ip(ip):
        return {"malicious": False, "risk_score": 0, "vendor_flags": 0, "detail": "Private IP"}

    # Hard-coded bad actors always flag
    if ip in _KNOWN_BAD:
        return {
            "malicious":    True,
            "risk_score":   95,
            "vendor_flags": 20,
            "detail":       f"Known malicious IP {ip} (signature match)",
        }

    # Random 3 % chance any other public IP gets flagged (realistic base-rate)
    if random.random() < 0.03:
        score = random.randint(55, 90)
        flags = random.randint(2, 12)
        return {
            "malicious":    True,
            "risk_score":   score,
            "vendor_flags": flags,
            "detail":       f"Suspicious IP {ip} flagged by {flags} vendors (score {score})",
        }

    return {"malicious": False, "risk_score": 0, "vendor_flags": 0, "detail": "Clean"}
