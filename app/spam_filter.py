def classify_email(subject: str, body: str, sender: str) -> str:

    spam_keywords = [
        'cash prize', 'win now', 'click here', 'lottery', 'urgent', 'you won',
        'reward', 'claim now', 'gift card', 'free iphone', 'verify account',
        'card details', 'otp', 'credentials', 'limited time', 'offer'
    ]
    ott_keywords = [
        'hotstar', 'zee5', 'netflix', 'prime video', 'sony liv', 'aha', 'voot'
    ]
    phishing_keywords = [
        'password', 'bank', 'account locked', 'ssn', 'credit card', 'wire transfer',
        'payment link', 'reset password'
    ]
    university_keywords = [
        'university', 'professor', 'course', 'exam', 'semester', 'department',
        'registrar', 'admissions'
    ]
    university_domains = ['.edu', '@college.edu', '@university.edu']

    text_lower = f"{subject} {body}".lower().strip()
    sender_lower = sender.lower()

    # Edge case: empty email → suspicious
    if not text_lower and not sender_lower:
        return 'SPAM'

    # University → INBOX
    if any(sender_lower.endswith(dom) or dom in sender_lower for dom in university_domains):
        return 'INBOX'
    if any(word in text_lower for word in university_keywords):
        return 'INBOX'

    # OTT / spam / phishing → SPAM
    if any(word in text_lower for word in ott_keywords):
        return 'SPAM'
    if any(word in text_lower for word in spam_keywords):
        return 'SPAM'
    if any(word in text_lower for word in phishing_keywords):
        return 'SPAM'

    return 'INBOX'
