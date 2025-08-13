def classify_email(text):
    university_keywords = ['university', 'professor','congratulations', 'course', 'exam', 'semester', 'department']
    spam_keywords = ['cash prize', 'win now', 'click here', 'congratulations', 'lottery', 'urgent', 'phone', 'links', 'card details', 'otp', 'link', 'credentials', 'details', 'you won']
    junk_keywords = ['zee5', 'hotstar', 'netflex']

    text_lower = text.lower()
    if any(word in text_lower for word in university_keywords):
        return "Inbox"
    elif any(word in text_lower for word in spam_keywords):
        return "Spam"
    elif any(word in text_lower for word in junk_keywords) :
        return "Junk"
    return "Inbox"
def is_spam(snippet, spam_keywords=None):
    if not spam_keywords:
        return False
    snippet = snippet or ""
    return any(keyword in snippet for keyword in spam_keywords)
