from flask import Blueprint, request, render_template, session, redirect, url_for, jsonify
from .spam_filter import classify_email, is_spam
from .ip_locator import locate_ip, extract_sender_ip
from .gmail_service import get_gmail_service, fetch_messages, get_message_details, login, oauth2callback as oauth2callback_handler

main = Blueprint('main', __name__)

@main.route('/', methods=['GET'])
def index_get():
    return render_template('index.html')

@main.route('/classify', methods=['POST'])
def index_post():
    email_text = request.form.get('email') or (request.json.get('email') if request.is_json else None)
    ip_address = request.form.get('ip') or (request.json.get('ip') if request.is_json else None)

    if not email_text or not ip_address:
        return jsonify({'error': 'Both email and ip are required'}), 400

    classification = classify_email(email_text)
    location = locate_ip(ip_address) if classification == 'Spam' else "N/A"

    if request.is_json:
        return jsonify({
            'classification': classification,
            'location': location
        })
    return render_template('index.html', result=classification, location=location)


@main.route('/login')
def login_router():
    return login()

@main.route('/oauth2callback', endpoint='oauth2callback')
def oauth2callback():
    return oauth2callback_handler()

@main.route('/inbox_view', methods=['GET'])
def inbox_view():
    inbox = []
    spam = []
    if 'credentials' not in session:
        return redirect(url_for('main.login'))

    service = get_gmail_service(session['credentials'])
    messages = fetch_messages(service)

    email_data = []
    for msg in messages:
        headers, snippet, payload = get_message_details(service, msg['id'])
        ip = extract_sender_ip(headers)
        snippet = snippet or ""

        if 'university' in snippet.lower():
            label = 'Inbox'
        elif is_spam(snippet):
            label = 'Spam'
        else:
            label = 'Inbox'

        if label == 'Inbox':
            inbox.append((headers, snippet))
        else:
            spam.append((headers, snippet))

        location = locate_ip(ip) if label == 'Spam' else 'N/A'

        email_data.append({
            'snippet': snippet,
            'ip': ip,
            'label': label,
            'location': location
        })

    return render_template('emails.html', emails=email_data)
