# app/security_utils.py

def is_suspicious_device(ip_address: str) -> bool:
    """
    Detects if an IP address likely belongs to a smartwatch or IoT device.
    You can expand this list of patterns later based on your dataset.
    """
    if not ip_address:
        return False

    # Known private / IoT / smartwatch IP patterns (examples)
    suspicious_prefixes = [
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "192.0.2.", "198.51.100.", "203.0.113."
    ]

    return any(ip_address.startswith(prefix) for prefix in suspicious_prefixes)
