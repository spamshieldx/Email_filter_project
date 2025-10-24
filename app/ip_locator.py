import re
import requests
from flask import current_app, has_app_context
# Patterns
IPV4_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b'

# Private/reserved network starts (simple check)
PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.", "169.254.",  # link local
)

# Simplified IPv4 numeric validator (ensure each octet <=255)
def _valid_ipv4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def _is_private_ipv4(ip):
    try:
        if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
            return True
        if ip.startswith("172."):
            second = int(ip.split('.')[1])
            return 16 <= second <= 31
        return False
    except Exception:
        return True  # err on safe side

def extract_sender_ip(headers):
    """
    Returns first public IPv4 or IPv6 found in Received headers (from earliest hop to latest).
    Gmail contains multiple Received entries; we iterate from last to first (earliest hop).
    If no public IP found returns None.
    """
    if not headers:
        return None

    try:
        received_headers = [h['value'] for h in headers if h.get('name','').lower() == 'received']
        if not received_headers:
            return None

        # Gmail often puts most recent first — examine in reverse to find originating IP
        for line in reversed(received_headers):
            # IPv4 candidates
            for match in re.findall(IPV4_PATTERN, line):
                if _valid_ipv4(match) and not _is_private_ipv4(match):
                    return match
            # IPv6 candidate
            match_v6 = re.search(IPV6_PATTERN, line)
            if match_v6:
                # no deep validation for v6 here
                return match_v6.group(0)
    except Exception:
        current_app.logger.exception("Error parsing headers for IP")
    return None

from flask import current_app, has_app_context
import requests

def locate_ip(ip):
    """
    Query ip-api.com for ip geolocation. Returns dict:
      {"ip": ip, "city": "...", "country": "..."} or None on failure.
    Uses current_app.cache when available.
    Works both inside and outside Flask context.
    """
    if not ip:
        return None

    # ✅ Safe cache handling
    cache = None
    if has_app_context():
        cache = getattr(current_app, 'cache', None)

    # Check cache if available
    if cache:
        cached = cache.get(f"iploc:{ip}")
        if cached:
            return cached

    try:
        # ✅ Use HTTPS for reliability
        resp = requests.get(
            f"https://ip-api.com/json/{ip}?fields=status,message,country,city,query,lat,lon",
            timeout=5
        )

        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                result = {
                    "ip": data.get('query'),
                    "city": data.get('city') or None,
                    "country": data.get('country') or None
                }

                if cache:
                    cache.set(f"iploc:{ip}", result)
                return result
            else:
                if has_app_context():
                    current_app.logger.info(
                        f"ip-api returned failure for {ip}: {data.get('message')}"
                    )

    except requests.RequestException as e:
        if has_app_context():
            current_app.logger.exception(f"ip-api request failed for {ip}: {e}")

    return None

def is_suspicious_device(ip):
    # Example IP range patterns for smartwatch or IoT devices
    watch_ip_patterns = ["172.16.", "192.0.2.", "198.51.100."]
    return any(ip.startswith(p) for p in watch_ip_patterns)
