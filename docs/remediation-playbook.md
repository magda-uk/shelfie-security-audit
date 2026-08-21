# Shelfie API: Technical Remediation Playbook

This document provides technical remediation steps, configuration rules, and secure code implementations to address the vulnerabilities identified in the Security Assessment Report.

---

## 1. Remediation: Broken Access Control / IDOR (CWE-639)

### Issue Summary
Endpoints expose internal object IDs directly in URLs (`/users/<int:user_id>/library`), trusting client input without validating whether the authenticated user owns the resource.

### Implementation Steps
1. Transition endpoints to contextual routes (e.g., `/api/v1/me/library`).
2. Implement a custom `@token_required` decorator to validate incoming Bearer tokens.
3. Extract `user_id` strictly from the decoded JWT payload or session identity.

```python
# --- SECURE DECORATOR & ROUTE ---
from functools import wraps
from flask import request, jsonify
import jwt

SECRET_KEY = "your-secure-secret-key-from-env"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Authentication token missing'}), 401
        try:
            # Bearer <token>
            token_str = token.split(" ")[1]
            data = jwt.decode(token_str, SECRET_KEY, algorithms=["HS256"])
            current_user_id = data['user_id']
        except Exception:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        return f(current_user_id, *args, **kwargs)
    return decorated

@app.route('/api/v1/me/library/add_book', methods=['POST'])
@token_required
def add_user_book(current_user_id):
    payload = request.get_json()
    book_id = payload.get('book_id')
    db_utils.insert_book(current_user_id, book_id)
    return jsonify({"status": "success", "message": "Book added securely"}), 201
```
### Verification
* Attempt to modify another user's library using a forged JWT; verify the API returns 401 Unauthorized or 403 Forbidden.

---
## 2. Remediation: Rate Limiting on Authentication (CWE-307)
### Issue Summary
The /auth/login endpoint lacks rate limiting, allowing infinite automated brute-force and credential stuffing attacks.

### Implementation Steps
* Install and configure Flask-Limiter.

* Apply strict IP-based limits to the login route (e.g., 5 attempts per minute).

```Python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login authentication logic
    ...
```
### Verification
Send 6 consecutive POST requests to /auth/login via curl or Burp Repeater; confirm the 6th request triggers 429 Too Many Requests.

---
## 3. Remediation: Hardening & Secure Error Handling (CWE-200)
## Issue Summary
The application runs with debug=True in development and exposes internal exception tracebacks (str(e)) to clients.

## Implementation Steps
* Force debug=False and externalize credentials using python-dotenv.

* Implement centralized structured logging and sanitized 500 error handlers.

* Enforce HTTPS and HSTS headers via Flask-Talisman.

```python
import logging
from flask_talisman import Talisman

# Initialize security headers and HTTPS redirection
Talisman(app, force_https=True)

# Configure internal secure logging
logging.basicConfig(
    filename='security_events.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s'
)

@app.errorhandler(500)
def handle_500(error):
    logging.error(f"Internal Exception: {error}", exc_info=True)
    return jsonify({
        "error": "Internal Server Error",
        "message": "A system error occurred. Please contact security/support."
    }), 500
```
---
## 4. Remediation Checklist
* [x] Contextual JWT routing implemented for all user-bound resources.

* [x] Password storage validated with memory-hard hashing (Werkzeug/scrypt).

* [x] Brute-force throttling enforced via Flask-Limiter.

* [x] Raw database/system exceptions suppressed from API output.

* [x] HTTP headers hardened via Flask-Talisman (HSTS, CSP).