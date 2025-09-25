from app.spam_filter import classify_email

def test_university_domain_inbox():
    assert classify_email(
        subject="Exam schedule posted",
        body="Please check the registrar portal.",
        sender="registrar@dept.university.edu"
    ) == "INBOX"

def test_university_keywords_inbox():
    assert classify_email(
        subject="University announcement",
        body="Department meeting details inside.",
        sender="info@announce.example.com"
    ) == "INBOX"

def test_cash_prize_spam():
    assert classify_email(
        subject="Congratulations! You’ve won a cash prize",
        body="Click here to claim your reward.",
        sender="promo@mailer.example"
    ) == "SPAM"

def test_ott_promotions_spam():
    assert classify_email(
        subject="Hotstar annual plan discount",
        body="Grab your subscription now!",
        sender="offers@streaming.example"
    ) == "SPAM"

def test_phishing_keywords_spam():
    assert classify_email(
        subject="Reset your password",
        body="Your bank account has been locked. Click to reset password.",
        sender="security@bank.com"
    ) == "SPAM"

def test_empty_email_spam():
    assert classify_email(
        subject="",
        body="",
        sender=""
    ) == "SPAM"

def test_normal_email_inbox():
    assert classify_email(
        subject="Meeting Notes",
        body="Please find the attached notes for the meeting.",
        sender="colleague@company.com"
    ) == "INBOX"

def test_smartwatch_header_spam():
    headers = [{"name": "User-Agent", "value": "AppleWatch Mail/1.0"}]
    assert classify_email(
        subject="Meeting Reminder",
        body="This is a test email sent from a smartwatch.",
        sender="watchuser@example.com",
        headers=headers
    ) == "SPAM"

def test_university_domain_with_phishing_keyword_in_body():
    # University emails should still go to INBOX even if body has a suspicious word
    assert classify_email(
        subject="Course Registration",
        body="Please reset your password for portal login",
        sender="registrar@uni.edu"
    ) == "INBOX"
