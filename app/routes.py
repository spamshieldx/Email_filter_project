from flask import Blueprint, request, session, redirect, url_for, jsonify, current_app
from .spam_filter import classify_email
from .ip_locator import locate_ip, extract_sender_ip
from .gmail_service import (
    get_gmail_service, fetch_messages, get_message_details, modify_labels,
    login, oauth2callback as oauth2callback_handler
)
from collections import Counter
from werkzeug.exceptions import BadRequest

from .utils import paginate_list, normalize_sender, extract_header_value, safe_get_str

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
    Classify a single email. (Same contract as before)
    """
    try:
        data = request.get_json(force=True)
    except BadRequest:
        return api_error("invalid_json", 400)

    if not data or not isinstance(data, dict):
        return api_error("invalid_payload", 400)

    sender = (data.get("sender") or data.get("from") or "").strip()
    if not sender:
        return api_error("sender_required", 400)

    subject = data.get("subject") or data.get("email_subject") or ""
    body = data.get("body") or data.get("email_body") or ""
    headers = data.get("headers", None)

    sender_norm = normalize_sender(sender)
    label = classify_email(subject, body, sender_norm, headers=headers)
    current_app.logger.info(f"Classified email from {sender_norm} → {label}")

    ip = None
    location = None
    try:
        ip = extract_sender_ip(headers)
        if ip:
            loc_info = locate_ip(ip)
            if loc_info:
                city = loc_info.get("city")
                country = loc_info.get("country")
                location = f"{city}, {country}" if city and country else (country or None)
    except Exception:
        current_app.logger.exception("Failed to extract or locate IP for /classify")

    return jsonify({
        "folder": label,
        "folder_type": label,
        "ip": ip,
        "location": location
    })

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

def _get_pagination_params(default_page_size=20):
    page = request.args.get("page", 1)
    page_size = request.args.get("page_size", default_page_size)
    try:
        page = int(page)
    except Exception:
        page = 1
    try:
        page_size = int(page_size)
    except Exception:
        page_size = default_page_size
    return page, page_size

@main.route('/inbox_view', methods=['GET'])
def inbox_view():
    """
    Fetch messages and return classification + ip + location. Does NOT change labels.
    Supports pagination: ?page=1&page_size=20
    """
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    try:
        service = get_gmail_service(session.get('credentials'))
    except Exception:
        current_app.logger.exception("Failed to build Gmail service")
        return api_error("invalid_credentials", 401)

    max_fetch = current_app.config.get('MAX_FETCH_MESSAGES', 20)
    # For pagination we fetch up to MAX_FETCH_MESSAGES and then paginate server-side
    messages = fetch_messages(service, max_results=max_fetch)

    email_data = []
    for msg in messages:
        headers, snippet, _ = get_message_details(service, msg['id'])
        snippet = snippet or ""
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender_raw = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        sender = normalize_sender(sender_raw)
        if not sender:
            continue

        ip = extract_sender_ip(headers)
        label = classify_email(subject, snippet, sender, headers=headers)
        location_info = locate_ip(ip) if ip and label == 'SPAM' else None
        location = f"{location_info.get('city')}, {location_info.get('country')}" if location_info else (None if ip else "N/A")

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

    # paginate
    page, page_size = _get_pagination_params(default_page_size=20)
    page_items, meta = paginate_list(email_data, page, page_size)
    return jsonify({"emails": page_items, "pagination": meta})

@main.route('/fetch_all_emails', methods=['GET'])
def fetch_all_emails():
    """
    Fetch raw Gmail emails (no classification). Supports pagination.
    """
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
        sender_raw = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        sender = normalize_sender(sender_raw)
        all_emails.append({
            "id": msg['id'],
            "threadId": msg.get("threadId", ""),
            "subject": subject,
            "sender": sender,
            "snippet": snippet,
            "headers": headers
        })

    page, page_size = _get_pagination_params(default_page_size=20)
    page_items, meta = paginate_list(all_emails, page, page_size)
    current_app.logger.info(f"Fetched {len(all_emails)} raw emails from Gmail")
    return jsonify({"emails": page_items, "pagination": meta})

@main.route('/process_emails', methods=['POST'])
def process_emails():
    """
    Classify emails and update Gmail labels. Returns summary.
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
        sender_raw = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        sender = normalize_sender(sender_raw)
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

@main.route('/stats', methods=['GET'])
def stats():
    """
    Lightweight stats: folder-wise counts + top spam countries.
    Supports ?page & ?page_size in case you want to paginate message-level info.
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
    per_message = []

    for m in messages:
        headers, snippet, _ = get_message_details(service, m['id'])
        snippet = snippet or ""
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender_raw = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        sender = normalize_sender(sender_raw)
        if not sender:
            continue

        label = classify_email(subject, snippet, sender, headers=headers)
        folder_counter[label] += 1

        if label == 'SPAM':
            ip = extract_sender_ip(headers)
            loc = locate_ip(ip) if ip else None
            if loc and loc.get('country'):
                spam_country_counter[loc.get('country')] += 1

        per_message.append({"id": m['id'], "sender": sender, "label": label})

    # paginate per_message (optional)
    page, page_size = _get_pagination_params(default_page_size=20)
    page_items, meta = paginate_list(per_message, page, page_size)

    return jsonify({
        "total_checked": len(messages),
        "folder_counts": dict(folder_counter),
        "top_spam_countries": spam_country_counter.most_common(5),
        "messages": page_items,
        "pagination": meta
    })

@main.route('/bulk_classify', methods=['POST'])
def bulk_classify():
    """
    Classify a list of emails provided in the request.
    Supports pagination query params for returned list: ?page=1&page_size=20
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
        sender_raw = email.get("sender") or email.get("from") or ""
        sender = normalize_sender(sender_raw)
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

    page, page_size = _get_pagination_params(default_page_size=20)
    page_items, meta = paginate_list(results, page, page_size)
    return jsonify({"classified_emails": page_items, "total": len(results), "pagination": meta})

@main.route('/ip_geolocate', methods=['POST'])
def ip_geolocate():
    try:
        data = request.get_json(force=True)
    except BadRequest:
        return api_error("invalid_json", 400)
    if not data or not isinstance(data, dict):
        return api_error("invalid_payload", 400)
    headers = data.get("headers", [])
    ip = extract_sender_ip(headers)
    if not ip:
        return jsonify({"ip": None, "location": None, "error": "no-sender-ip-found"}), 200
    location = locate_ip(ip)
    if not location:
        return jsonify({"ip": ip, "location": None, "note": "private-or-invalid-ip"}), 200
    return jsonify({"ip": ip, "location": location}), 200

@main.route('/test_gmail_fetch', methods=['GET'])
def test_gmail_fetch():
    """
    Non-destructive final Gmail fetch test.
    Purpose: confirm Gmail fetch works, returns message count and sample IDs + any errors.
    Does NOT change labels.
    Query params:
      - max_fetch (overrides app.MAX_FETCH_MESSAGES)
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
        current_app.logger.exception("Invalid credentials for test_gmail_fetch")
        return api_error("invalid_credentials", 401)

    errors = []
    messages = []
    try:
        raw = fetch_messages(service, max_results=max_fetch)
        messages = raw or []
    except Exception as e:
        current_app.logger.exception("Error fetching messages during test")
        errors.append(str(e))

    sample_ids = [m.get('id') for m in messages][:10]
    return jsonify({
        "success": True if messages else False,
        "requested_max": max_fetch,
        "fetched_count": len(messages),
        "sample_ids": sample_ids,
        "errors": errors
    })

@main.route('/folder_counts', methods=['GET'])
def folder_counts():
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    service = get_gmail_service(session['credentials'])
    messages = fetch_messages(service, max_results=50)

    counts = {"INBOX": 0, "SPAM": 0}
    for msg in messages:
        headers, snippet, _ = get_message_details(service, msg['id'])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        label = classify_email(subject, snippet or "", sender)
        counts[label] = counts.get(label, 0) + 1

    return jsonify({"folder_counts": counts})

from collections import Counter

@main.route('/spam_country_stats', methods=['GET'])
def spam_country_stats():
    if 'credentials' not in session:
        return redirect(url_for('main.login_route'))

    service = get_gmail_service(session['credentials'])
    messages = fetch_messages(service, max_results=50)

    spam_countries = []

    for msg in messages:
        headers, snippet, _ = get_message_details(service, msg['id'])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "")
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "")
        label = classify_email(subject, snippet or "", sender)
        if label == 'SPAM':
            ip = extract_sender_ip(headers)
            location = locate_ip(ip)
            if location != "Unknown" and "," in location:
                _, country = location.split(",", 1)
                spam_countries.append(country.strip())

    top_countries = Counter(spam_countries).most_common(5)
    return jsonify({"top_spam_countries": top_countries})
