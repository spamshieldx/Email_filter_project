from app.spam_filter import is_spam

def test_inbox_email():
    assert is_spam("This is a notice from the university") == "Inbox"

def test_spam_email():
    assert is_spam("Congratulations! You've won a cash prize") == "Spam"
