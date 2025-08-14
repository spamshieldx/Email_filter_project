import os
import base64
import re
from flask import redirect, request, session, url_for
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'


def creds_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('main.oauth2callback', _external=True)
    auth_url, _ = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        include_granted_scopes='true'
    )
    return redirect(auth_url)

def oauth2callback():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('main.oauth2callback', _external=True)
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session['credentials'] = creds_to_dict(creds)
    return redirect(url_for('main.inbox_view'))

def get_gmail_service(token_info):
    creds = Credentials.from_authorized_user_info(token_info)
    if not creds.valid and creds.refresh_token:
        creds.refresh(Request())
        session['credentials'] = creds_to_dict(creds)
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
