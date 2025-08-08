import geocoder
import re

def extract_sender_ip(headers):
    received_headers = [h['value']for h in headers if h['name'].lower()== 'received']
    for line in received_headers:
        match = re.search(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', line)
        if match:
            return match.group(1)
        return "IP Not Found"

def locate_ip(ip):
    g = geocoder.ip(ip)
    if g.ok:
        return f"{g.city}, {g.country}"
    return "Unknown"
