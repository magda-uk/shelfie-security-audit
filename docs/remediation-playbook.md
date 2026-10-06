# Shelfie API: Technical Remediation Playbook

This document provides technical remediation steps, configuration rules, and secure code implementations to address the vulnerabilities identified in the Security Assessment Report.

---

## 1. Remediation: Broken Access Control / IDOR (CWE-639)
 **STRIDE / MITRE Mapping:** Tampering & Information Disclosure | **T1190** (Exploit Public-Facing Application) & **T1078** (Valid Accounts)

### Issue Summary
Endpoints expose internal object IDs directly in URLs (`/users/<int:user_id>/library/add_book`), trusting client input without validating whether the requester owns the target resource.

### Implementation Steps
1. Transition endpoints to contextual routes (`/api/v1/me/library` or `/user/library`).
2. Implement a custom `@token_required` decorator (or `@login_required` via Flask-Login) to validate incoming tokens stored in `HttpOnly`, `Secure`, `SameSite=Strict` cookies or Authorization headers.
3. Extract `user_id` strictly from the cryptographically verified JWT payload or server session.

```python
# --- SECURE DECORATOR & ROUTE ---
from functools import wraps
from flask import request, jsonify
import jwt

# Load secret strictly from OS environment variables (Never hardcoded)
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            return jsonify({"error": "Authentication token missing"}), 401
        try:
            token_str = token.split(" ")[1]
            data = jwt.decode(token_str, SECRET_KEY, algorithms=["HS256"])
            current_user_id = data["user_id"]
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "Token is invalid or expired"}), 401
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
* Attempt to modify another user's library using an unauthenticated reuest or forged JWT in Burp Suite; verify the API rejects the request with `401 Unauthorized`.

---
## 2.Remediation: Rate Limiting & Credential Protection (CWE-287 / CWE-307)
### STRIDE / MITRE Mapping: 
Spoofing & Denial of Service | T1110 (Brute Force / Credential Stuffing) & T1499 (Endpoint DoS)
### Issue Summary
The POST /auth/login endpoint lacks rate limiting, allowing infinite automated brute-force and credential stuffing attempts against user accounts.

### Implementation Steps
* Install and configure `Flask-Limiter` paired with host-level `Fail2Ban` rules.

* Apply strict IP-based limits to authentication routes (e.g., 5 attempts per minute).

* Ensure password hashing uses memory-hard algorithms (`scrypt` via Werkzeug 3.1.8 or upgraded to `Argon2id` per NIST SP 800-63B).


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
    # Login authentication & token logic
    return jsonify({"status": "success"}), 200
    ...
```
### Verification
Send 6 consecutive `POST` requests to `/auth/login` via `curl` or Burp Intruder/Repeater; confirm the 6th request triggers `429 Too Many Requests`.

---
## 3. Remediation: Transport Hardening, Secrets & Error Handling (CWE-200)
### STRIDE / MITRE Mapping
Information Disclosure & Elevation of Privilege | **T1082** (System Info Discovery), **T1059.006** (Python RCE) & **T1557** (Adversary-in-the-Middle)
## Issue Summary
The application runs with debug=True (exposing the Werkzeug interactive Debugger PIN `120-454-171`), leaks raw exception tracebacks (`details: str(e)`) on malformed JSON, relies on `print()` statements, and stores plaintext credentials in `config.py`.

## Implementation Steps
* Enforce `debug=False` in production and load `GOOGLE_BOOKS_API_KEY and MySQL credentials via environment variables.

* Replace `print()` statements with Python's `logging` module (excluding plaintext passwords) for SIEM (`ELK Stack / Sentry`) ingestion and sanitise global `500` error responses.

* Deploy behind an `Nginx` reverse proxy (TLS 1.3) and enforce HTTPS/HSTS headers via `Flask-Talisman`.

```python
import logging
from flask_talisman import Talisman

app.config["DEBUG"] = False

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
    # Log full stack trace internally; never expose str(e) to the client
    logging.error(f"Internal Exception: {error}", exc_info=True)
    return jsonify({
        "error": "Internal Server Error",
        "message": "A system error occurred. Please contact security/support."
    }), 500
```
### Verification
* Send malformed JSON to `POST /users/42/books/1/reviews/add_review` in Burp Suite and verify a generic JSON error is returned with no Werkzeug traceback leaks, while the full exception is recorded in `security_events.log`.
---
## 4. Remediation: Input Validation & Database Least Privilege (CWE-79 / CWE-89)
### STRIDE / MITRE Mapping
Tampering | **T1059.007** (JavaScript Execution) & **T1565.001** (Stored Data Manipulation)
### Issue Summary
The API accepts unsanitised `<script>alert(1)</script>` payloads in book reviews, uses f-strings wrapped in `int()` for SQL `LIMIT` clauses, and lacks database-level privilege separation.
### Implementation Steps
1. Validate incoming JSON payloads with `Pydantic` and apply Unicode `NFKC` normalisation in `models.py`.

2. Restrict the MySQL service account strictly to Data Manipulation Language (`DML`) commands and read-only `SQL Views`, revoking Data Definition Language (`DDL`) permissions per NIST SP 800-53 Rev. 5.

```python
import unicodedata
from pydantic import BaseModel, Field, field_validator

class ReviewCreateSchema(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    review_text: str = Field(..., min_length=1, max_length=2000)

    @field_validator("review_text")
    @classmethod
    def normalise_and_sanitise(cls, value: str) -> str:
        # Apply NFKC normalisation to prevent Unicode homograph bypasses
        normalised = unicodedata.normalize("NFKC", value.strip())
        if "<script" in normalised.lower():
            raise ValueError("Invalid HTML/script tags detected in review payload")
        return normalised
```

```sql
-- MySQL Principle of Least Privilege (PoLP): Grant DML only, deny DDL (DROP/ALTER)
CREATE USER 'shelfie_api'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'StrongEnvPassword!' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON shelfie.* TO 'shelfie_api'@'localhost';
FLUSH PRIVILEGES;
```

## 5. Remediation Checklist
* [x] Contextual JWT routing implemented for all user-bound resources (`CWE-639`).

* [x] Password storage validated with memory-hard hashing (`Werkzeug 3.1.8/scrypt`).

* [x] Brute-force throttling enforced via `Flask-Limiter (CWE-307)`.

* [x] Raw database/system exceptions (`str(e)`) and Werkzeug Debugger PIN suppressed from API output (`CWE-200`).

* [x] HTTP headers hardened via `Flask-Talisman (force_https=True`, HSTS, CSP).
* [x] Input schema validation (`Pydantic + NFKC`) and MySQL Least Privilege (`DML-only + REQUIRE SSL`) defined.

---

---

## Document Control & Author Sign-Off

* **Authored & Architected by:** Magda Dominguez
* **Role:** Security Architecture & Technical Remediation Lead
* **Certifications:** BCS CISMP | Microsoft SC-900
* **Scope:** Post-audit Low-Level Design (LLD) remediation patterns, STRIDE/MITRE ATT&CK control mapping, and secure Python/Flask & MySQL implementation guidelines.
* **Cybersecurity Portfolio:** [Blue Team, SOC & AppSec Showcase](https://github.com/magda-uk/soc-analyst-showcase) | [@magda-uk](https://github.com/magda-uk)
* **LinkedIn:** [linkedin.com/in/magda-d-infosec](https://www.linkedin.com/in/magda-d-infosec)