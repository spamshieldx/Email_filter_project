from flask import Blueprint, request, session, redirect, url_for, jsonify, current_app, Response
import requests
from datetime import datetime

from .dummy_data import generate_dummy_emails
from .spam_filter import classify_email
from .ip_locator import locate_ip, extract_sender_ip
from google.oauth2.credentials import Credentials
from flask import Flask, send_file
from .gmail_service import (
    get_gmail_service, fetch_messages, get_message_details, modify_labels,
    login, oauth2callback as oauth2callback_handler, revoke_and_clear
)
from collections import Counter
from werkzeug.exceptions import BadRequest

from .utils import paginate_list, normalize_sender, extract_header_value, safe_get_str

main = Blueprint('main', __name__)

def api_error(message="bad_request", code=400):
    return jsonify({"error": message}), code

@main.route("/api/health", methods=['GET'])
def health():
    return jsonify(status='ok')

@main.route('/', methods=['GET'])
def index_get():
    return jsonify({"message": "Welcome to Email Filter API"})

@main.route("/api/classify", methods=['POST'])
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
    folder_type = label
    reason = None

    try:
        ip = extract_sender_ip(headers)
        if ip:
            loc_info = locate_ip(ip)
            if loc_info:
                city = loc_info.get("city")
                country = loc_info.get("country")
                location = f"{city}, {country}" if city and country else (country or None)

            # Check for suspicious device IP (custom logic)
            from .security_utils import is_suspicious_device  # Import helper safely
            if is_suspicious_device(ip):
                folder_type = "blocked"
                reason = "Blocked Smart Watch IP"
                current_app.logger.warning(f"🚨 Suspicious device detected — IP {ip} blocked.")
    except Exception:
        current_app.logger.exception("Failed to extract or locate IP for /classify")

    return jsonify({
        "folder": label,
        "folder_type": folder_type,
        "ip": ip,
        "location": location,
        "reason": reason
    })


@main.route("/api/login", methods=["GET"])
def api_login():
    """
    API endpoint for login simulation or Gmail redirect.
    For now, just mark the user session as active for testing.
    """
    try:
        session["user"] = "demo_user"
        current_app.logger.info("User session created for demo_user")
        return jsonify({"success": True, "message": "User logged in successfully"})
    except Exception as e:
        current_app.logger.exception("Login route failed")
        return jsonify({"error": f"login_failed: {e}"}), 500


@main.route("/login", methods=["GET"])
def legacy_login_redirect():
    """
    Backward compatible route (redirects to /api/login).
    """
    return redirect(url_for("main.api_login"))

@main.route("/api/oauth2callback")
def oauth2callback():
    """
    Handles Google OAuth callback, stores Gmail credentials in session,
    then redirects to React Inbox page instead of raw JSON view.
    """
    try:
        oauth2callback_handler()
        current_app.logger.info(" Gmail OAuth successful — redirecting to frontend inbox page")
        # Redirect to React Inbox Page
        return redirect("http://localhost:5173/inbox")
    except Exception as e:
        current_app.logger.exception("OAuth2 callback failed")
        return jsonify({"error": "oauth2_failed", "details": str(e)}), 500


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

@main.route("/api/inbox_view", methods=['GET'])
def inbox_view():
    """
    Inbox view that returns classified emails.
    If user is not logged in, return 401 JSON instead of redirect.
    """
    if "user" not in session and "credentials" not in session:
        return jsonify({"error": "unauthorized"}), 401

    # If Gmail connected, fetch from Gmail; else return demo emails
    try:
        if "credentials" in session:
            service = get_gmail_service(session["credentials"])
            messages = fetch_messages(service, max_results=10)
            email_data = []

            for msg in messages:
                headers, snippet, _ = get_message_details(service, msg["id"])
                subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
                sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
                sender_norm = normalize_sender(sender)
                label = classify_email(subject, snippet, sender_norm, headers=headers)
                ip = extract_sender_ip(headers)
                location = locate_ip(ip) if ip else None

                email_data.append({
                    "id": msg["id"],
                    "subject": subject or "(No Subject)",
                    "sender": sender_norm,
                    "ip": ip,
                    "folder_type": label,
                    "location": location.get("city") if isinstance(location, dict) else "Unknown"
                })
        else:
            # Demo emails for manual login users
            email_data = [
                {
                    "subject": "Welcome to the University",
                    "sender": "admin@university.edu",
                    "ip": "127.0.0.1",
                    "folder_type": "INBOX",
                    "location": "Localhost"
                },
                {
                    "subject": "Claim your prize now!",
                    "sender": "spammer@fake.com",
                    "ip": "203.0.113.45",
                    "folder_type": "SPAM",
                    "location": "Unknown"
                }
            ]

        return jsonify({"emails": email_data})
    except Exception as e:
        current_app.logger.exception("Inbox view failed")
        return api_error(f"inbox_error: {e}", 500)

@main.route("/api/fetch_all_emails", methods=["GET"])
def fetch_all_emails():
    """
    Fetch all Gmail emails (or dummy emails if not logged in with Gmail).
    Supports pagination.
    """
    from .dummy_data import generate_dummy_emails  # Import inside function to avoid circular import

    # Get pagination parameters
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 20))

    if "credentials" not in session:
        # Generate 50 dummy emails for demo/testing mode
        emails = generate_dummy_emails(50)
        total = len(emails)
        start = (page - 1) * page_size
        end = start + page_size

        paginated = emails[start:end]
        return jsonify({
            "page": page,
            "page_size": page_size,
            "total": total,
            "emails": paginated,
            "source": "dummy_data"
        })

    try:
        service = get_gmail_service(session.get("credentials"))
    except Exception:
        current_app.logger.exception("Invalid credentials for fetch_all_emails")
        return api_error("invalid_credentials", 401)

    max_fetch = current_app.config.get("MAX_FETCH_MESSAGES", 50)
    messages = fetch_messages(service, max_results=max_fetch)

    all_emails = []
    for msg in messages:
        headers, snippet, _ = get_message_details(service, msg["id"])
        snippet = snippet or ""
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        sender_raw = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
        sender = normalize_sender(sender_raw)

        all_emails.append({
            "id": msg["id"],
            "threadId": msg.get("threadId", ""),
            "subject": subject,
            "sender": sender,
            "snippet": snippet,
            "headers": headers,
        })

    total = len(all_emails)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = all_emails[start:end]

    current_app.logger.info(f"Fetched {len(all_emails)} raw emails from Gmail")

    return jsonify({
        "page": page,
        "page_size": page_size,
        "total": total,
        "emails": paginated,
        "source": "gmail_api"
    })

@main.route("/api/process_emails", methods=['POST'])
def process_emails():
    """
    Classify emails and update Gmail labels. Returns summary.
    """
    if 'credentials' not in session:
        return redirect(url_for('main.api_login'))

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

@main.route("/api/stats", methods=['GET'])
def stats():
    """
    Lightweight stats: folder-wise counts + top spam countries.
    Supports ?page & ?page_size in case you want to paginate message-level info.
    """
    if 'credentials' not in session:
        return redirect(url_for('main.api_login'))

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

@main.route("/api/bulk_classify", methods=['POST'])
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

@main.route("/api/ip_geolocate", methods=['POST'])
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

@main.route("/api/test_gmail_fetch", methods=['GET'])
def test_gmail_fetch():
    """
    Non-destructive final Gmail fetch test.
    Purpose: confirm Gmail fetch works, returns message count and sample IDs + any errors.
    Does NOT change labels.
    Query params:
      - max_fetch (overrides app.MAX_FETCH_MESSAGES)
    """
    if 'credentials' not in session:
        return redirect(url_for('main.api_login'))

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

@main.route("/api/folder_counts", methods=['GET'])
def folder_counts():
    if 'credentials' not in session:
        return redirect(url_for('main.api_login'))

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

@main.route("/api/spam_country_stats", methods=['GET'])
def spam_country_stats():
    if 'credentials' not in session:
        return redirect(url_for('main.api_login'))

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

from .gmail_service import revoke_and_clear

@main.route("/api/logout", methods=['POST'])
def logout():
    """Revoke Gmail token and clear session"""
    creds_data = session.get("credentials")
    if creds_data:
        creds = Credentials(**creds_data)
        revoke = requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': creds.token},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )
        if revoke.status_code == 200:
            session.clear()
            return jsonify({"message": "Logout successful"}), 200
        else:
            return jsonify({"error": "Failed to revoke token"}), 400
    return jsonify({"message": "No active session"}), 200

@main.route("/api/revoke", methods=['POST'])
def revoke():
    try:
        resp = revoke_and_clear()
        return jsonify(resp), 200
    except Exception as e:
        return api_error(f"revoke_failed: {e}", 500)

@main.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    # Normally you would save this in a database
    current_app.logger.info(f"User signed up: {username} ({email})")
    return jsonify({"success": True, "message": "User registered successfully"})


@main.route("/api/login_manual", methods=["POST"])
def login_manual():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    # validate user from DB
    if username == "admin" and password == "1234":
        session["user"] = username
        current_app.logger.info(f"Manual login success for {username}")
        return jsonify({"success": True, "message": "Login successful"})

    current_app.logger.warning(f"Invalid manual login attempt for {username}")
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@main.route("/docs")
def api_docs():
    return send_file("docs.md")

@main.route("/download_csv")
def download_csv():
    import csv
    from io import StringIO
    emails = generate_dummy_emails(30)
    si = StringIO()
    writer = csv.DictWriter(si, fieldnames=emails[0].keys())
    writer.writeheader()
    writer.writerows(emails)
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=emails.csv"})
