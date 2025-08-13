import os
import base64
import re
from flask import redirect, request, session, url_for
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

# ✅ Allow HTTP for local development (disable in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'


# Step 1: Login route
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('main.oauth2callback', _external=True)

    authorization_url, _ = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        include_granted_scopes='true'
    )
    return redirect(authorization_url)


# Step 2: OAuth callback
def oauth2callback():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('main.oauth2callback', _external=True)
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session['credentials'] = creds_to_dict(creds)

    return redirect(url_for('main.inbox_view'))


def read_emails():
    if 'credentials' not in session:
        return redirect(url_for('main.login_router'))

    creds = Credentials(**session['credentials'])

    if not creds.valid and creds.refresh_token:
        creds.refresh(Request())
        session['credentials'] = creds_to_dict(creds)

    service = build('gmail', 'v1', credentials=creds)
    messages = fetch_messages(service)

    email_data = []
    for msg in messages:
        headers, snippet , payload = get_message_details(service, msg['id'])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), '')
        body = extract_email_body_from_payload(payload)
        ip = extract_ip_from_headers(headers)

        email_data.append({
            'subject': subject,
            'sender': sender,
            'body': body,
            'ip': ip
        })

    return email_data


def extract_email_body_from_payload(payload):
    def _extract_from_part(part):
        mime = part.get('mimeType', '')
        if mime == 'text/plain' and part.get('body', {}).get('data'):
            return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace')
        for sub in part.get('parts', []):
            text = _extract_from_part(sub)
            if text:
                return text
        return None

    parts = payload.get('parts', [])
    if parts:
        for p in parts:
            text = _extract_from_part(p)
            if text:
                return text

    body = payload.get('body', {}).get('data')
    if body:
        return base64.urlsafe_b64decode(body).decode('utf-8', errors='replace')

    return ''


def extract_ip_from_headers(headers):
    received = [h['value'] for h in headers if h['name'].lower() == 'received']
    for header in reversed(received):  # earliest first
        m = re.search(r'\[?(\d{1,3}(?:\.\d{1,3}){3})]?', header)
        if m:
            return m.group(1)
    return 'Unknown'


def creds_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

def get_gmail_service(token_info):
    creds = Credentials.from_authorized_user_info(token_info)
    return build('gmail', 'v1', credentials=creds)

def fetch_messages(service, max_results=10):
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    return results.get('messages', [])


def get_message_details(service, message_id):
    msg = service.users().messages().get(userId='me', id=message_id).execute()
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])
    snippet = msg.get('snippet', '') or ''
    return headers, snippet, payload
