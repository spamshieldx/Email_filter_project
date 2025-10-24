# Gmail OAuth → Fetch → Classify Flow

This document explains the end-to-end flow used by the app to connect to Gmail, fetch messages, extract sender IPs, locate IPs and classify messages.

## Flow steps

1. **Obtain Google OAuth credentials**
   - Create a Google Cloud project and OAuth client (type: **Web application**).
   - Add authorized redirect URI: `http://localhost:5000/api/oauth2callback`
   - Download `credentials.json` and place it at `app/credentials.json` or set `CLIENT_SECRETS_FILE` env var.

2. **Start the Flask server**
   - `export FLASK_APP=run.py`
   - `python run.py` (app runs on port 5000 by default)

3. **Initiate OAuth**
   - Frontend or user visits `/api/login` (or `/login` which redirects).
   - For full Google OAuth, call `/login` (which currently marks demo session) or visit the OAuth start route if implemented to use real Google flow.

4. **Google redirects back**
   - Google will redirect to `/api/oauth2callback` with `code`.
   - App exchanges code for tokens and stores `session['credentials']` = credentials dict.

5. **Fetch messages**
   - `/api/fetch_all_emails` or `/api/test_gmail_fetch` will use `get_gmail_service(session['credentials'])` and call Gmail API to list messages, then call `get_message_details` for each message.

6. **Extract sender IP**
   - `extract_sender_ip(headers)` inspects Received headers (reverses them to find earliest hop) and returns first public IPv4 / IPv6.

7. **IP geolocation**
   - `locate_ip(ip)` calls `http://ip-api.com/json/{ip}` (cached) to get `city` and `country`. If private/invalid, returns `None`.

8. **Classification**
   - `classify_email(subject, body, sender, headers)` returns `"INBOX"` or `"SPAM"` (or `"blocked"` in routes when device/ip suspicious).
   - Rules:
     - `.edu` and known university domains → INBOX
     - spam keywords (lottery, claim, free, etc.) → SPAM
     - user-agent headers containing watch/fitbit/garmin → SPAM (and possibly blocked)

## Running tests

- Mocked tests (fast, CI-safe):


- Live tests (manual only; ensure credentials available):
1. Create a JSON credentials dump with the `session['credentials']` shape (token, refresh_token, token_uri, client_id, client_secret, scopes).
2. Set environment:
   ```
   export LIVE_GMAIL_TEST=1
   export TEST_CREDENTIALS_FILE=/path/to/session_credentials.json
   pytest tests/test_gmail_integration.py::test_gmail_fetch_live -q
   ```

## Troubleshooting
- If token refresh fails, check `client_secret` and `refresh_token` validity.
- If ip-api rate-limits, use caching and reduce requests by increasing `CACHE_DEFAULT_TIMEOUT`.
