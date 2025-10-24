import random
from datetime import datetime

def generate_dummy_emails(n=20):
    spam_keywords = ["win", "cash", "offer", "lottery", "click", "subscribe"]
    emails = []
    for i in range(n):
        is_spam = random.choice([True, False])
        subject = random.choice(spam_keywords) + " " + random.choice(["deal", "reward", "gift"])
        sender = f"user{i}@{'spamdomain.com' if is_spam else 'university.edu'}"
        emails.append({
            "id": i,
            "subject": subject,
            "sender": sender,
            "folder_type": "spam" if is_spam else "inbox",
            "ip": f"192.168.1.{random.randint(2,254)}",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    return emails
