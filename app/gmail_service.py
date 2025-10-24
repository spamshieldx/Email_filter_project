import os
from flask import redirect, request, session, url_for, current_app, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import requests

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
CLIENT_SECRETS_FILE = 'app/credentials.json'

def _get_client_secrets_file():
    # Prefer Flask app config when available
    try:
        return current_app.config.get("CLIENT_SECRETS_FILE", "credentials.json")
    except Exception:
        return os.environ.get("CLIENT_SECRETS_FILE", "credentials.json")

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
    try:
        client_secrets = _get_client_secrets_file()
        flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow.redirect_uri = url_for('main.oauth2callback', _external=True)
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            include_granted_scopes='true'
        )
        return redirect(auth_url)
    except Exception as e:
        current_app.logger.exception("OAuth initiation failed")
        return jsonify({"error": "oauth_init_failed", "message": str(e)}), 500


def oauth2callback():
    try:
        client_secrets = _get_client_secrets_file()
        flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow.redirect_uri = url_for('main.oauth2callback', _external=True)
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        session['credentials'] = creds_to_dict(creds)
        return redirect(url_for('main.inbox_view'))
    except Exception as e:
        current_app.logger.exception("OAuth callback failed")
        return jsonify({"error": "oauth_callback_failed", "message": str(e)}), 500


def get_gmail_service(token_info):
    if not token_info:
        raise ValueError("missing_credentials")

    try:
        creds = Credentials.from_authorized_user_info(token_info)
    except Exception as e:
        current_app.logger.exception("Invalid token info when creating Credentials")
        raise ValueError("invalid_token_info") from e
    if not creds.valid and creds.refresh_token:
        try:
            creds.refresh(Request())
            session['credentials'] = creds_to_dict(creds)
        except Exception as e:
            current_app.logger.exception("Failed to refresh Gmail credentials")
            raise
    return build('gmail', 'v1', credentials=creds)


def fetch_messages(service, max_results=20):
    try:
        results = service.users().messages().list(userId='me', maxResults=max_results).execute()
        return results.get('messages', []) or []
    except Exception:
        current_app.logger.exception("Failed to fetch Gmail messages")
        return []


def get_message_details(service, message_id):
    try:
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        payload = msg.get('payload', {})
        headers = payload.get('headers', [])
        snippet = msg.get('snippet', '')
        return headers, snippet, payload
    except Exception:
        current_app.logger.exception(f"Failed to get message {message_id}")
        return [], "", {}


def modify_labels(service, msg_id, classification):
    try:
        if classification.upper() == "SPAM":
            body = {"removeLabelIds": ["INBOX"], "addLabelIds": ["SPAM"]}
        else:
            body = {"addLabelIds": ["INBOX"], "removeLabelIds": ["SPAM"]}
        service.users().messages().modify(userId='me', id=msg_id, body=body).execute()
        return True
    except Exception:
        current_app.logger.exception(f"Failed to modify labels for {msg_id}")
        return False


def revoke_and_clear():
    """Revoke Gmail OAuth token and clear session."""
    creds = session.get('credentials')
    if not creds:
        return {"status": "no_credentials"}

    token = creds.get('token')
    try:
        requests.post('https://oauth2.googleapis.com/revoke',
                      params={'token': token},
                      headers={'content-type': 'application/x-www-form-urlencoded'})
    except Exception:
        current_app.logger.exception("Revoke request failed")
    session.pop('credentials', None)
    return {"status": "revoked"}
