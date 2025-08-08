import os
import base64
import re
from flask import redirect, request, session, url_for
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# ✅ Allow HTTP for local development (disable in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# OAuth configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'


# Step 1: Login route — initiates OAuth flow
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES
    )

    # ✅ Matches route defined in routes.py
    flow.redirect_uri = url_for('main.oauth2callback', _external=True)

    authorization_url, _ = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    return redirect(authorization_url)


# Step 2: Callback route — handles token exchange after consent
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES
    )
    flow.redirect_uri = url_for('main.oauth2callback', _external=True)

    # ⚠️ Important: get token from redirected URL
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials

    # Store credentials in session
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

    return redirect(url_for('main.inbox_view'))


# Step 3: Read emails
def read_emails():
    if 'credentials' not in session:
        # ✅ Use correct route name
        return redirect(url_for('main.login_router'))

    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    results = service.users().messages().list(userId='me', maxResults=10).execute()
    messages = results.get('messages', [])

    email_data = []
    for msg in messages:
        msg_detail = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
        headers = msg_detail['payload']['headers']

        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), '')
        body = extract_email_body(msg_detail)
        ip = extract_ip_address(headers)

        email_data.append({
            'subject': subject,
            'sender': sender,
            'body': body,
            'ip': ip
        })

    return email_data


# Step 4: Extract plain text from body
def extract_email_body(msg_detail):
    try:
        parts = msg_detail['payload'].get('parts', [])
        for part in parts:
            if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
        if msg_detail['payload'].get('mimeType') == 'text/plain':
            return base64.urlsafe_b64decode(msg_detail['payload']['body']['data']).decode('utf-8')
    except Exception as e:
        return f"Error extracting body: {e}"
    return ""


# Step 5: Extract IP
def extract_ip_address(headers):
    received_headers = [h['value'] for h in headers if h['name'] == 'Received']
    if received_headers:
        match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)]', received_headers[-1])
        if match:
            return match.group(1)
    return "Unknown"
def get_gmail_service(token_info):
    creds = Credentials.from_authorized_user_info(token_info)
    service = build('gmail', 'v1', credentials=creds)
    return service
def fetch_messages(service, max_results=10):
    results = service.users().message().list(userId='me', maxResult=max_results).execute()
    messages = results.get('messages', [])
    return messages
def get_message_details(service, message_id):
    msg = service.users().messages().get(userId='me', id=message_id, formate='full').execute()
    payload = msg.get('payload', {})
    header = payload.get('header', {})
    snippet = msg.get('snippet')
    return header,snippet
