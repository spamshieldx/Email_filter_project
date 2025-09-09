import re
import geocoder

# Regex for IPv4 and IPv6
IPV4_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
IPV6_PATTERN = r'([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}'

def extract_sender_ip(headers):
    """
    Extract the first valid public sender IP from email headers.
    """
    received_headers = [h['value'] for h in headers if h['name'].lower() == 'received']
    for line in received_headers:
        # Try IPv4
        match_v4 = re.search(IPV4_PATTERN, line)
        if match_v4:
            ip = match_v4.group(0)
            if not ip.startswith(("10.", "192.168.", "172.16.")):  # ignore private IPs
                return ip
        # Try IPv6
        match_v6 = re.search(IPV6_PATTERN, line)
        if match_v6:
            return match_v6.group(0)
    return "IP Not Found"

def locate_ip(ip):
    """
    Get approximate City, Country from IP address.
    """
    if ip == "IP Not Found":
        return "Unknown"
    try:
        g = geocoder.ip(ip)
        if g.ok and (g.city or g.country):
            return f"{g.city or 'Unknown City'}, {g.country or 'Unknown Country'}"
    except Exception as e:
        print(f"Error locating IP: {e}")
    return "Unknown"
