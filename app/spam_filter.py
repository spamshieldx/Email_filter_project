def classify_email(subject, body, sender, headers=None):
    """
    Classify emails into INBOX or SPAM based on sender, content, and headers.

    Parameters:
        subject (str | None): Email subject
        body (str | None): Email body
        sender (str | None): Sender email address
        headers (list[dict] | dict | str | None): Optional email headers

    Returns:
        str: "INBOX" or "SPAM"
    """
    try:
        # Ensure inputs are strings
        subject = (subject or "") if not isinstance(subject, dict) else ""
        body = (body or "") if not isinstance(body, dict) else ""
        sender = (sender or "") if not isinstance(sender, dict) else ""

        # Normalize to lower for checks
        subject_l = subject.lower()
        body_l = body.lower()
        sender_l = sender.lower()

        # 0️⃣ Empty email check (body or subject empty)
        if not subject_l.strip() and not body_l.strip():
            return "SPAM"

        # 1️⃣ University email heuristic
        # Accept all university-related domains and any ".edu"
        university_domains = ["university.edu", "college.edu", "institute.edu", "uni.edu", ".edu"]
        if any(domain in sender_l for domain in university_domains):
            return "INBOX"

        # 2️⃣ Spam keywords heuristic
        spam_keywords = [
            "cash prize", "winner", "reward", "subscribe now", "free", "hotstar", "ott", "lottery", "claim now", "claim your prize"
        ]
        content = f"{subject_l} {body_l}"
        if any(keyword in content for keyword in spam_keywords):
            return "SPAM"

        # 3️⃣ Device header heuristic: block smartwatches
        if headers:
            # Convert headers to a list of dicts if needed
            if isinstance(headers, dict):
                headers = [headers]
            elif isinstance(headers, str):
                parts = headers.split(":", 1)
                headers = [{"name": parts[0].strip(), "value": parts[1].strip()}] if len(parts) == 2 else []

            for h in headers:
                if isinstance(h, dict):
                    name = (h.get('name') or "").lower()
                    value = (h.get('value') or "").lower()
                    if name in ('user-agent', 'x-device', 'x-mailer') and any(dev in value for dev in ('watch', 'applewatch', 'fitbit', 'garmin')):
                        return "SPAM"

        # Default fallback
        return "INBOX"
    except Exception:
        # In case of unexpected input, treat as spam (safe default)
        return "SPAM"
