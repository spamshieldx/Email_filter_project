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
