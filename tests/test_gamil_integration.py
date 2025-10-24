# tests/test_gmail_integration.py
import os
import pytest
import json
from unittest.mock import MagicMock

# If you want to run the live test, export LIVE_GMAIL_TEST=1 and ensure
# session/credentials are available in your Flask test client environment.
LIVE_TEST_FLAG = os.environ.get("LIVE_GMAIL_TEST", "0") == "1"

from app.routes import main as routes_blueprint
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    # Use a short cache timeout during tests
    app.config['CACHE_DEFAULT_TIMEOUT'] = 1
    with app.test_client() as client:
        with app.app_context():
            yield client

def make_fake_msg(msgid, subject="Test", from_addr="spammer@example.com", snippet="hello"):
    headers = [
        {"name": "Subject", "value": subject},
        {"name": "From", "value": from_addr},
        {"name": "Received", "value": "from unknown (203.0.113.5)"}  # a public IP style
    ]
    return {"id": msgid, "threadId": f"t-{msgid}", "headers": headers, "snippet": snippet}

def test_gmail_fetch_mocked(monkeypatch, client):
    """
    Mock the Gmail service to simulate message fetch and message details.
    This exercises fetch_all_emails, process_emails and stats endpoints without real Gmail.
    """
    # Prepare 3 fake messages
    fake_messages = [make_fake_msg(str(i), subject=f"Spam offer {i}", from_addr=f"spam{i}@promo.com") for i in range(3)]

    # Mock get_gmail_service to return a fake service object
    fake_service = MagicMock()

    # Mock messages().list().execute() -> returns items with id
    list_resp = {"messages": [{"id": m["id"]} for m in fake_messages]}
    fake_service.users.return_value.messages.return_value.list.return_value.execute.return_value = list_resp

    # Mock messages().get().execute() to return full message dict (we map by id)
    def fake_get(userId, id, format):
        # find message by id
        m = next((x for x in fake_messages if x["id"] == id), None)
        return MagicMock(execute=MagicMock(return_value={
            "id": id,
            "snippet": m["snippet"] if m else "",
            "payload": {"headers": m["headers"] if m else []}
        }))

    fake_service.users.return_value.messages.return_value.get.side_effect = lambda userId, id, format='full': fake_get(userId, id, format)

    # Patch the helper functions used in routes
    monkeypatch.setattr("app.routes.get_gmail_service", lambda creds: fake_service)
    monkeypatch.setattr("app.routes.fetch_messages", lambda service, max_results=20: list_resp["messages"])
    monkeypatch.setattr("app.routes.get_message_details", lambda service, message_id: (
        next((m["headers"] for m in fake_messages if m["id"] == message_id), []),
        next((m["snippet"] for m in fake_messages if m["id"] == message_id), ""),
        {}
    ))
    # monkeypatch locate_ip to return a deterministic result
    monkeypatch.setattr("app.routes.locate_ip", lambda ip: {"ip": ip, "country": "Testland", "city": "Testville"})

    # Set a demo credentials session so endpoints don't redirect
    with client.session_transaction() as sess:
        sess['credentials'] = {"token": "fake", "refresh_token": "fake", "token_uri": "https://oauth2.googleapis.com/token",
                               "client_id": "fake", "client_secret": "fake", "scopes": ["https://www.googleapis.com/auth/gmail.modify"]}

    # Call fetch_all_emails (it will use our monkeypatched functions)
    resp = client.get("/api/fetch_all_emails?page=1&page_size=10")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["source"] == "gmail_api"
    assert data["total"] == len(fake_messages)
    assert len(data["emails"]) == len(fake_messages)

    # Call stats endpoint
    resp2 = client.get("/api/stats")
    assert resp2.status_code == 200
    stats = resp2.get_json()
    assert "folder_counts" in stats
    assert "messages" in stats

@pytest.mark.skipif(not LIVE_TEST_FLAG, reason="Live Gmail tests disabled. Set LIVE_GMAIL_TEST=1 to enable.")
def test_gmail_fetch_live(client):
    """
    Live test. Requires:
      - Valid credentials in session (session['credentials'])
      - Credentials must have permission to access Gmail.
    This should be run manually when you have an OAuth setup.
    """
    # The test will attempt to call /api/test_gmail_fetch which uses your real Gmail credentials
    with client.session_transaction() as sess:
        # Ensure session has credentials before running
        creds_path = os.environ.get("TEST_CREDENTIALS_FILE")
        if not creds_path or not os.path.exists(creds_path):
            pytest.skip("TEST_CREDENTIALS_FILE not provided or missing.")
        with open(creds_path, "r") as fh:
            sess['credentials'] = json.load(fh)

    resp = client.get("/api/test_gmail_fetch?max_fetch=5")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "fetched_count" in data
    # If Gmail is accessible, fetched_count should be >= 0
    assert isinstance(data["fetched_count"], int)
