#!/usr/bin/env bash
set -euo pipefail

# Usage:
# 1) export CLIENT_SECRETS_FILE=app/credentials.json
# 2) python run.py  (start app)
# 3) open browser to http://localhost:5000/api/login  (or follow your frontend)
#
# To run the live pytest:
# export LIVE_GMAIL_TEST=1
# export TEST_CREDENTIALS_FILE=/path/to/session_credentials.json
# pytest tests/test_gmail_integration.py::test_gmail_fetch_live -q

echo "1) Make sure you have CLIENT_SECRETS_FILE set and Flask running."
echo "2) To run mocked tests: pytest tests/test_gmail_integration.py::test_gmail_fetch_mocked -q"
echo "3) To run live tests (manual): set LIVE_GMAIL_TEST=1 and provide TEST_CREDENTIALS_FILE path"
