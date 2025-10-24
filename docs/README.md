# 📧 Gmail Spam Classifier with Flask & OAuth

## 🚀 Overview
A Flask-based application that connects to Gmail via OAuth, fetches emails, classifies them into **Inbox or Spam**, and identifies **spammer IP location** using the `ip-api` service.

---

## 🛠️ Features
- Gmail OAuth 2.0 authentication
- Fetch, analyze, and classify emails
- Detect spam using defined keyword patterns
- Identify spammer’s geolocation from IP headers
- Pagination, caching, and error handling
- REST API with Swagger documentation
- Automated tests with 20+ dummy emails

---

## ⚙️ Setup Instructions

### 1. Clone & Install
```bash
git clone <repo_url>
cd gmail_spam_filter
pip install -r requirements.txt

export FLASK_ENV=development
export CLIENT_SECRETS_FILE=credentials.json

python run.py
