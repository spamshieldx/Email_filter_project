from app.ip_locator import extract_sender_ip, locate_ip

def test_extract_sender_ip_ipv4():
    headers = [{"name": "Received", "value": "from mail.example.com (123.45.67.89)"}]
    ip = extract_sender_ip(headers)
    assert ip == "123.45.67.89"

def test_extract_sender_ip_ipv6():
    headers = [{"name": "Received", "value": "from server (2001:0db8:85a3:0000:0000:8a2e:0370:7334)"}]
    ip = extract_sender_ip(headers)
    assert ip.startswith("2001:0db8")

def test_locate_ip_success():
    ip = "8.8.8.8"  # Google DNS
    location = locate_ip(ip)
    assert isinstance(location, str)
    assert "Unknown" not in location  # Should return a valid location

def test_locate_ip_failure():
    ip = "999.999.999.999"  # Invalid IP
    location = locate_ip(ip)
    assert location == "Unknown"