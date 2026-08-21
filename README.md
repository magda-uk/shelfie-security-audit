# Shelfie REST API: Security Audit & Remediation Plan

[![OWASP Top 10](https://img.shields.io/badge/Compliance-OWASP%20Top%2010-red.svg)](#)
[![Stack](https://img.shields.io/badge/Stack-Python%20%7C%20Flask%20%7C%20MySQL-blue.svg)](#)
[![Audit Status](https://img.shields.io/badge/Audit-Completed%20%26%20Documented-success.svg)](#)

## 1. Executive Summary
A comprehensive security assessment and code review of the **Shelfie API** (a Flask-based RESTful library management backend). The audit identified critical access control and authentication flaws that expose user libraries, private notes, and reviews to unauthorized manipulation, alongside key configuration risks.

> **Full Audit Report:** The complete academic report with IEEE references is available in [`/reports/full-security-audit.pdf`](./reports/).

---

## 2. Assessment Scope & Methodology
* **Target Application:** Shelfie REST API (Flask, MySQL, Python).
* **Testing Methodology:** Black-box & Grey-box dynamic analysis using **Burp Suite Community Edition**, alongside static code review of `app.py`, `utils.py`, and `db_utils.py`.
* **Frameworks Evaluated:** OWASP Top 10 (2021), NIST SP 800-63B, and CWE standards.

---

## 3. Vulnerability Findings Matrix

| ID | Vulnerability / Weakness | Severity | CWE | Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Broken Object Level Authorization (IDOR) | **Critical** | CWE-639 | Identified & Fix Designed |
| **SEC-02** | Broken Authentication & Missing Session Tokens | **High** | CWE-287 | Identified & Fix Designed |
| **SEC-03** | Security Misconfiguration (Active Debugger & Trace Leaks) | **Medium** | CWE-200 | Identified & Fix Designed |
| **SEC-04** | Missing Rate Limiting on Authentication Endpoints | **Medium** | CWE-307 | Identified & Fix Designed |
| **SEC-05** | Potential Stored XSS / Unsanitized Input Payload | **Low** | CWE-79 | Identified & Fix Designed |

---

## 4. Key Findings & Technical Remediation

### SEC-01: Broken Access Control (IDOR) on User Library Routes
* **Vulnerability:** Endpoints rely directly on user input from the URL (e.g., `POST /users/<user_id>/library/add_book`) without validating if the requester matches the authenticated identity.
* **Exploitation:** Verified using Burp Suite by manipulating the `user_id` parameter to inject books into arbitrary accounts without authentication.
* **Remediation:** Enforce stateless JWT or session-bound contextual routes (e.g., `/api/v1/me/library`) where identity is extracted strictly from the validated token header.

```python
# --- BEFORE (Vulnerable to IDOR) ---
@app.route('/users/<int:user_id>/library/add_book', methods=['POST'])
def add_book(user_id):
    # Trusts user_id directly from the client request path
    db_utils.insert_book(user_id, request.json['book_id'])
    return jsonify({"status": "success"}), 201

# --- AFTER (Secure Implementation with Token Context) ---
@app.route('/api/v1/me/library/add_book', methods=['POST'])
@token_required
def add_book(current_user):
    # user_id is securely extracted from the validated session/JWT
    db_utils.insert_book(current_user.id, request.json['book_id'])
    return jsonify({"status": "success"}), 201
```
### SEC-02 & SEC-03: Security Misconfigurations & Error Handling
* **Vulnerability**: The Flask application runs in debug=True mode, exposing an interactive Debugger PIN and returning raw execution tracebacks (details: str(e)) to clients.

* **Remediation**:

  * 1. Enforce environment variable controls for configuration management.

  * 2. Implement global JSON error handling to prevent stack trace leaks.

  * 3. Deploy behind a reverse proxy (Nginx) enforcing HTTPS via Flask-Talisman.

```python
# --- SECURE ERROR HANDLING IMPLEMENTATION ---
@app.errorhandler(500)
def handle_internal_error(error):
    # Log the full traceback internally for SOC/Dev investigation
    logger.error(f"Internal Server Error: {error}", exc_info=True)
    # Return a generic, sanitized response to the client
    return jsonify({
        "error": "Internal Server Error",
        "message": "An unexpected error occurred. Please try again later."
    }), 500  
```
---
## 5. Remediation Roadmap
* [x] Identify and map vulnerabilities against OWASP Top 10 & CWE standards.

* [ ] Migrate database access patterns to parameterized ORM models (SQLAlchemy).

* [ ] Implement rate-limiting via Flask-Limiter to throttle credential stuffing attempts.

* [ ] Enforce HTTPS and security headers (HSTS, CSP) using Flask-Talisman.

* [ ] Configure structured logging (Python logging) for SIEM ingestion.
  