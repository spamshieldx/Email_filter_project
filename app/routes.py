from flask import Blueprint, request, session, redirect, url_for, jsonify, current_app
from .spam_filter import classify_email
from .ip_locator import locate_ip, extract_sender_ip
from .gmail_service import (
    get_gmail_service, fetch_messages, get_message_details, modify_labels,
    login, oauth2callback as oauth2callback_handler
)

main = Blueprint('main', __name__)

@main.route('/health', methods=['GET'])
def health():
    return jsonify(status='ok')

@main.route('/', methods=['GET'])
def index_get():
    return jsonify({"message": "Welcome to Email Filter API"})

@main.route('/classify', methods=['POST'])
def classify_email_route():
    data = request.get_json(silent=True) or {}
    subject = data.get("email_subject", "")
    body = data.get("email_body", "")
    sender = data.get("sender", "")

    if not subject or not body or not sender:
        return jsonify({"error": "email_subject, email_body, and sender are required"}), 400

    label = classify_email(subject, body, sender)
    current_app.logger.info(f"Classified email from {sender} → {label}")
    return jsonify({"folder": label})

@main.route('/login')
def login_route():
    return login()

@main.route('/oauth2callback')
def oauth2callback():
    return oauth2callback_handler()

@main.route('/inbox_view', methods=['GET'])
def inbox_view():
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    service = get_gmail_service(session['credentials'])
    messages = fetch_messages(service)

    email_data = []
    for msg in messages:
        headers, snippet, _ = get_message_details(service, msg['id'])
        snippet = snippet or ""

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        ip = extract_sender_ip(headers)

        label = classify_email(subject, snippet, sender)
        location = locate_ip(ip) if label == 'SPAM' else 'N/A'

        current_app.logger.info(f"Processed email from {sender} | Subject: {subject} | Label: {label} | IP: {ip} | Location: {location}")

        email_data.append({
            'subject': subject,
            'sender': sender,
            'snippet': snippet,
            'ip': ip,
            'label': label,
            'location': location
        })

    return jsonify(emails=email_data)

@main.route('/process_emails', methods=['POST'])
def process_emails():
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    service = get_gmail_service(session['credentials'])
    messages = fetch_messages(service)

    changed = 0
    for m in messages:
        headers, snippet, _ = get_message_details(service, m['id'])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        label = classify_email(subject, snippet or "", sender)
        modify_labels(service, m['id'], label)
        changed += 1

        current_app.logger.info(f"Updated Gmail labels for {sender} → {label}")

    return jsonify({"processed": changed})
