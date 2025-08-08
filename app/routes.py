from flask import Blueprint, request, render_template, session, redirect, url_for
from .spam_filter import classify_email, is_spam
from .ip_locator import locate_ip, extract_sender_ip
from .gmail_service import get_gmail_service, fetch_messages, get_message_details, login, oauth2callback as oauth2callback_handler, read_emails

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email_text = request.form['email']
        ip_address = request.form['ip']

        classification = classify_email(email_text)
        location = locate_ip(ip_address) if classification == 'Spam' else "N/A"

        return render_template('index.html', result=classification, location=location)
    return render_template('index.html')


@main.route('/login')
def login_router():
    return login()


@main.route('/oauth2callback', endpoint='oauth2callback')
def oauth2callback():
    return oauth2callback_handler()


@main.route('/inbox_view')
def inbox_view():
    if 'credentials' not in session:
        return redirect(url_for('main.login'))

    # Get Gmail API service
    service = get_gmail_service(session['credentials'])
    messages = fetch_messages(service)

    email_data = []

    for msg in messages:
        headers, snippet = get_message_details(service, msg['id'])
        ip = extract_sender_ip(headers)

        # Classify email
        label = 'Inbox' if 'university' in snippet.lower() else 'Spam' if is_spam(snippet) else 'Inbox'

        # Locate IP only for spam
        location = locate_ip(ip) if label == 'Spam' else 'N/A'

        email_data.append({
            'snippet': snippet,
            'ip': ip,
            'label': label,
            'location': location
        })

    return render_template('emails.html', emails=email_data)
    return render_template('emails.html')