import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_bulk_classification(client):
    dummy_emails = [
        {"email_subject": "Exam Results", "email_body": "Check with registrar office", "sender": "prof@uni.edu"},
        {"email_subject": "Cash Prize!", "email_body": "Click here to claim", "sender": "spam@promo.com"},
        {"email_subject": "Hotstar Offer", "email_body": "Subscribe now", "sender": "ott@streaming.com"},
        {"email_subject": "Password Reset", "email_body": "Reset your bank password", "sender": "alert@bank.com"},
        {"email_subject": "Semester Timetable", "email_body": "Registrar released dates", "sender": "dept@university.edu"},
        {"email_subject": "Free iPhone", "email_body": "Claim your free iphone", "sender": "scam@random.com"},
        {"email_subject": "Payment Link", "email_body": "Wire transfer instructions", "sender": "fraud@money.com"},
        {"email_subject": "Netflix Discount", "email_body": "Get subscription at half price", "sender": "offers@ott.com"},
        {"email_subject": "University Conference", "email_body": "All professors invited", "sender": "events@uni.edu"},
        {"email_subject": "Urgent Action Needed", "email_body": "Verify your account", "sender": "security@fakebank.com"},
        {"email_subject": "Registrar Circular", "email_body": "New semester starts soon", "sender": "registrar@college.edu"},
        {"email_subject": "Gift Card", "email_body": "Get your Amazon gift card now", "sender": "promo@scam.com"},
        {"email_subject": "Course Registration", "email_body": "Register before deadline", "sender": "student@university.edu"},
        {"email_subject": "Lottery Winner", "email_body": "You won the lottery!", "sender": "lotto@spam.com"},
        {"email_subject": "Professor Meeting", "email_body": "Faculty meeting details", "sender": "dean@uni.edu"},
        {"email_subject": "Zee5 Annual Plan", "email_body": "Discounts for early users", "sender": "deals@streaming.com"},
        {"email_subject": "Wire Transfer Alert", "email_body": "Send payment immediately", "sender": "scammer@fraud.com"},
        {"email_subject": "Exam Notification", "email_body": "Semester exam schedule", "sender": "exam@dept.edu"},
        {"email_subject": "Claim Now", "email_body": "Click to claim your prize", "sender": "spammy@promo.com"},
        {"email_subject": "Admissions Open", "email_body": "Apply for new semester", "sender": "admissions@uni.edu"},
    ]

    results = []
    for email in dummy_emails:
        response = client.post("/classify", json=email)
        assert response.status_code == 200
        data = response.get_json()
        assert "folder" in data
        assert "folder_type" in data
        results.append({"email": email, "classified_as": data["folder"]})

    assert len(results) >= 20

    # Print output for debug (pytest -s will show)
    for r in results:
        print(r)
