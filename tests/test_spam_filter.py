from app.spam_filter import classify_spam

def test_inbox_email():
    assert classify_spam("This is a notice from the university") == "Inbox"

def test_spam_email():
    assert classify_spam("Congratulations! You've won a cash prize") == "Spam"
