from flask import Blueprint, request, session, redirect, url_for, jsonify, current_app
from .spam_filter import classify_email
from .ip_locator import locate_ip, extract_sender_ip
from .gmail_service import (
    get_gmail_service, fetch_messages, get_message_details, modify_labels,
    login, oauth2callback as oauth2callback_handler
)
from collections import Counter
from werkzeug.exceptions import BadRequest

main = Blueprint('main', __name__)

def api_error(message="bad_request", code=400):
    return jsonify({"error": message}), code

@main.route('/health', methods=['GET'])
def health():
    return jsonify(status='ok')

@main.route('/', methods=['GET'])
def index_get():
    return jsonify({"message": "Welcome to Email Filter API"})

@main.route('/classify', methods=['POST'])
def classify_email_route():
    """
    Classify a single email based on subject, body, sender, and headers.
    Works with Postman CSV runner and supports 'subject' or 'email_subject'.
    """
    try:
        data = request.get_json(force=True)
    except BadRequest:
        return api_error("invalid_json", 400)

    if not data or not isinstance(data, dict):
        return api_error("invalid_payload", 400)

    # Get sender safely
    sender = (data.get("sender") or "").strip()
    if not sender:
        return api_error("sender_required", 400)

    # Get subject/body from either standard or CSV-compatible keys
    subject = data.get("subject") or data.get("email_subject") or ""
    body = data.get("body") or data.get("email_body") or ""
    headers = data.get("headers", None)

    label = classify_email(subject, body, sender, headers=headers)
    current_app.logger.info(f"Classified email from {sender} → {label}")
    return jsonify({"folder": label, "folder_type": label})

@main.route('/login')
def login_route():
    try:
        return login()
    except Exception:
        current_app.logger.exception("Login route failed")
        return api_error("login_failed", 500)

@main.route('/oauth2callback')
def oauth2callback():
    return oauth2callback_handler()

@main.route('/inbox_view', methods=['GET'])
def inbox_view():
    """
    Fetch messages and return classification + ip + location. Does NOT change labels.
    """
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    try:
        service = get_gmail_service(session.get('credentials'))
    except Exception as e:
        current_app.logger.exception("Failed to build Gmail service")
        return api_error("invalid_credentials", 401)

    max_fetch = current_app.config.get('MAX_FETCH_MESSAGES', 20)
    messages = fetch_messages(service, max_results=max_fetch)

    email_data = []
    for msg in messages:
        headers, snippet, _ = get_message_details(service, msg['id'])
        snippet = snippet or ""

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "").strip()

        if not sender:
            continue

        ip = extract_sender_ip(headers)
        label = classify_email(subject, snippet, sender, headers=headers)
        location_info = locate_ip(ip) if ip and label == 'SPAM' else None
        location = f"{location_info.get('city')}, {location_info.get('country')}" if location_info else (None if ip else "N/A")

        current_app.logger.info(
            f"Processed email from {sender} | Subject: {subject} | Label: {label} | IP: {ip} | Location: {location}"
        )

        email_data.append({
            'id': msg['id'],
            'subject': subject,
            'sender': sender,
            'snippet': snippet,
            'ip': ip,
            'label': label,
            'location': location,
            'folder_type': label
        })

    return jsonify(emails=email_data)

@main.route('/process_emails', methods=['POST'])
def process_emails():
    """
    Classify emails and update Gmail labels. Returns summary of processed emails,
    counts by folder, and top 5 spam countries.
    """
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    try:
        service = get_gmail_service(session.get('credentials'))
    except Exception:
        current_app.logger.exception("Invalid or missing credentials")
        return api_error("invalid_credentials", 401)

    max_fetch = current_app.config.get('MAX_FETCH_MESSAGES', 20)
    messages = fetch_messages(service, max_results=max_fetch)

    processed_emails = []
    changed = 0
    folder_counter = Counter()
    spam_country_counter = Counter()

    for m in messages:
        headers, snippet, _ = get_message_details(service, m['id'])
        snippet = snippet or ""

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "").strip()
        if not sender:
            continue

        label = classify_email(subject, snippet, sender, headers=headers)

        ok = modify_labels(service, m['id'], label)
        if ok:
            changed += 1

        folder_counter[label] += 1

        if label == 'SPAM':
            ip = extract_sender_ip(headers)
            loc = locate_ip(ip) if ip else None
            if loc and loc.get('country'):
                spam_country_counter[loc.get('country')] += 1

        current_app.logger.info(f"Updated Gmail labels for {sender} → {label}")

        processed_emails.append({
            "id": m['id'],
            "subject": subject,
            "sender": sender,
            "label": label,
            "folder_type": label
        })

    top_spam_countries = spam_country_counter.most_common(5)
    return jsonify({
        "processed": len(processed_emails),
        "changed_labels": changed,
        "folder_counts": dict(folder_counter),
        "top_spam_countries": top_spam_countries,
        "emails": processed_emails
    })

@main.route('/fetch_all_emails', methods=['GET'])
def fetch_all_emails():
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    try:
        service = get_gmail_service(session.get('credentials'))
    except Exception:
        current_app.logger.exception("Invalid credentials for fetch_all_emails")
        return api_error("invalid_credentials", 401)

    max_fetch = current_app.config.get('MAX_FETCH_MESSAGES', 20)
    messages = fetch_messages(service, max_results=max_fetch)

    all_emails = []
    for msg in messages:
        headers, snippet, _ = get_message_details(service, msg['id'])
        snippet = snippet or ""

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "").strip()

        all_emails.append({
            "id": msg['id'],
            "threadId": msg.get("threadId", ""),
            "subject": subject,
            "sender": sender,
            "snippet": snippet,
            "headers": headers
        })

    current_app.logger.info(f"Fetched {len(all_emails)} raw emails from Gmail")
    return jsonify({"emails": all_emails})

@main.route('/stats', methods=['GET'])
def stats():
    """
    Lightweight stats: fetch folder-wise counts and top spam countries (classification only).
    """
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    try:
        max_fetch = int(request.args.get('max_fetch', current_app.config.get('MAX_FETCH_MESSAGES', 20)))
    except Exception:
        max_fetch = current_app.config.get('MAX_FETCH_MESSAGES', 20)

    try:
        service = get_gmail_service(session.get('credentials'))
    except Exception:
        current_app.logger.exception("Invalid credentials for stats")
        return api_error("invalid_credentials", 401)

    messages = fetch_messages(service, max_results=max_fetch)

    folder_counter = Counter()
    spam_country_counter = Counter()

    for m in messages:
        headers, snippet, _ = get_message_details(service, m['id'])
        snippet = snippet or ""

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "").strip()
        if not sender:
            continue

        label = classify_email(subject, snippet, sender, headers=headers)
        folder_counter[label] += 1

        if label == 'SPAM':
            ip = extract_sender_ip(headers)
            loc = locate_ip(ip) if ip else None
            if loc and loc.get('country'):
                spam_country_counter[loc.get('country')] += 1

    return jsonify({
        "total_checked": len(messages),
        "folder_counts": dict(folder_counter),
        "top_spam_countries": spam_country_counter.most_common(5)
    })

@main.route('/bulk_classify', methods=['POST'])
def bulk_classify():
    """
    Classify multiple emails in one request.
    Expects JSON with a list of emails.
    """
    try:
        data = request.get_json(force=True)
    except BadRequest:
        return api_error("invalid_json", 400)

    if not data or not isinstance(data, dict):
        return api_error("invalid_payload", 400)

    emails = data.get("emails", [])
    if not isinstance(emails, list) or not emails:
        return api_error("emails_list_required", 400)

    results = []
    for email in emails:
        sender = (email.get("sender") or "").strip()
        if not sender:
            results.append({"error": "sender_required"})
            continue

        subject = email.get("subject") or email.get("email_subject") or ""
        body = email.get("body") or email.get("email_body") or ""
        headers = email.get("headers", None)

        label = classify_email(subject, body, sender, headers=headers)
        results.append({
            "subject": subject,
            "sender": sender,
            "label": label,
            "folder_type": label
        })

    return jsonify({"classified_emails": results, "total": len(results)})

@main.route('/ip_geolocate', methods=['POST'])
def ip_geolocate():
    """
    Extract sender IP from headers and return geolocation.
    """
    try:
        data = request.get_json(force=True)
    except BadRequest:
        return api_error("invalid_json", 400)

    if not data or not isinstance(data, dict):
        return api_error("invalid_payload", 400)

    headers = data.get("headers", [])

    # Extract IP from headers
    ip = extract_sender_ip(headers)
    if not ip:
        return jsonify({"ip": None, "location": None, "error": "no-sender-ip-found"}), 200

    # Lookup location for public IP
    location = locate_ip(ip)
    if not location:
        return jsonify({
            "ip": ip,
            "location": None,
            "note": "private-or-invalid-ip"
        }), 200

    return jsonify({
        "ip": ip,
        "location": location
    }), 200

@main.route("/email_counts", methods=["GET"])
def email_counts():
    # For demo: query Gmail or classify stored emails
    counts = {"INBOX": 120, "SPAM": 45, "PROMOTIONS": 60}
    return jsonify(counts)

from collections import Counter

@main.route("/spam_by_country", methods=["GET"])
def spam_by_country():
    # Imagine you already classified and located spam
    spam_ips = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    countries = []
    for ip in spam_ips:
        loc = locate_ip(ip)
        if loc and loc.get("country"):
            countries.append(loc["country"])
    top5 = Counter(countries).most_common(5)
    return jsonify({"top_5": [{"country": c, "count": n} for c, n in top5]})

@main.route("/cleanup_spam", methods=["POST"])
def cleanup_spam():
    token_info = session.get("credentials")
    service = get_gmail_service(token_info)
    # pseudo logic: get spam messages and move/delete
    deleted = 10
    return jsonify({"deleted_spam_count": deleted, "status": "success"})
