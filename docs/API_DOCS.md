
# API Documentation (Auto-added)

## Auth / OAuth
- `/login` (GET) - starts OAuth flow (front-end redirect).  
- `/oauth2callback` (GET) - OAuth callback to exchange code for tokens.  
- `/revoke` (POST) - revoke token.  
- `/logout` (POST) - logout and clear session.

## Email analysis
- `/fetch_all_emails` (GET) - returns analyzed emails (supports `page`, `page_size` query params).  
- `/classify` (POST) - classify provided email content, returns `folder_type`.  
- `/download_csv` (GET) - (added) returns CSV of analyzed emails. Query params: `folder`, `limit`.  
- `/block_ip` (POST) - (added) block an IP address. JSON body: `{ "ip": "...", "reason": "..." }`.

## IP lookup
- `/locate_ip?ip=1.2.3.4` - uses ip-api to fetch geolocation for an IP.

## Notes
- Place your Google OAuth client credentials in `app/credentials.json` or set environment variables shown in `.env.example`.
- For large production deployments, replace simple JSON file storage for blocked IPs with a proper database.
