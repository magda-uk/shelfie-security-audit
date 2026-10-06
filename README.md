# Shelfie REST API: Security Architecture Audit, Threat Model & Remediation Plan 


[![OWASP Top 10](https://img.shields.io/badge/Compliance-OWASP%20Top%2010%20%7C%20API%20Top%2010-red.svg)](#)
[![Frameworks](https://img.shields.io/badge/Frameworks-STRIDE%20%7C%20MITRE%20ATT%26CK%20%7C%20NIST%20SP%20800--53-blueviolet.svg)](#)
[![Stack](https://img.shields.io/badge/Stack-Python%20%7C%20Flask%20%7C%20MySQL-blue.svg)](#)
[![Audit Status](https://img.shields.io/badge/Audit-Completed%20%26%20Documented-success.svg)](#)
[![Target Repo](https://img.shields.io/badge/Target%20Repo-Project%20Shelfie%20API-181717?logo=github)](https://github.com/magda-uk/Project-Shelfie-group-5-project)

## 1. Executive Summary
A comprehensive security architecture assessment, dynamic penetration test, and secure design remediation plan for the **Shelfie RESTful API** (a four-layer Python Flask and MySQL backend managing personal book libraries, reading progress, private quotes, and reviews).

While the baseline architecture implements strong foundational controls—including `scrypt` password hashing via Werkzeug 3.1.8, parameterised SQL queries (`%s`), socket-closing context managers, and `localhost` port `3306` binding—dynamic testing and static code reviews identified critical gaps in object-level authorisation, session management, runtime configuration, and secrets handling.


> 📄 **Full Technical Report:** The complete 25-page assessment with Burp Suite evidence and 77 IEEE academic references is available in [`/reports/full-security-audit.pdf`](./reports/full-security-audit.pdf).

> 💻 **Target Application Source Code:** The original four-layer Flask & MySQL codebase audited in this report can be found in the [**Project Shelfie Repository**](https://github.com/magda-uk/Project-Shelfie-group-5-project).

---

## 2. Assessment Scope & Methodology
* **Target Architecture:** Four-layer Defence-in-Depth backend (`app.py` presentation routing, `utils.py` and `models.py` validation and business logic, `db_utils.py` and `db_connection.py` data access, and `config.py` environment settings).
* **Testing Methodology:** Black-box and Grey-box dynamic analysis using **Burp Suite Community Edition**, alongside static code inspection and dependency auditing.
* **Standards & Frameworks Evaluated:** **STRIDE** Threat Modelling, **MITRE ATT&CK® Enterprise Matrix**, **OWASP Top 10 (2021)**, **OWASP API Security Top 10**, **NIST SP 800-63B** (Digital Identity), **NIST SP 800-53 Rev. 5** (Access Control & Least Privilege), **NIST SP 800-92** (Log Management), and **CWE**.

---

## 3. Architectural Deconstruction & Threat Model (STRIDE & MITRE ATT&CK®)

To evaluate the soundness of the **Shelfie API** design, the architecture was deconstructed across four core **Trust Boundaries** to map vulnerabilities into business risks (**Likelihood × Impact**):

1. **Boundary 1 (External Client -> Network / Reverse Proxy -> Flask Routing):** Untrusted HTTP traffic, URL path parameters (`/users/<user_id>`), and unthrottled authentication requests entering `app.py`.
2. **Boundary 2 (Flask Application -> Runtime & Configuration Environment):** Execution state (`debug=True`), error handling hooks (`str(e)`), and credential storage in `config.py`.
3. **Boundary 3 (Input Pipeline -> Domain Models & Validation Layer):** JSON payloads processed through `utils.py` and OOP alternative constructors in `models.py`.
4. **Boundary 4 (Data Access Layer -> MySQL Engine & Log Storage):** SQL execution in `db_utils.py` over port `3306` and local event output via `print()` statements.

### Vulnerability, Threat & Risk Mapping Matrix

| ID | Vulnerability & CWE | Trust Boundary | STRIDE Category | MITRE ATT&CK® Technique | Inherent Business Risk (Likelihood × Impact) | Architectural Security Control & Remediation | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **Broken Object Level Authorisation (IDOR)** *(CWE-639)* | Boundary 1 | **Tampering** & **Information Disclosure** | **T1190** (Exploit Public-Facing App) | **CRITICAL** *(High × High)*: Trivial URL tampering (`POST /users/43/library/add_book`) allows unauthenticated users to read or modify any user's private library, quotes, and reviews. | Shift to contextual routing (`/user/library`) using stateless **JWTs** (in `HttpOnly`, `Secure`, `SameSite=Strict` cookies) or **Flask-Login** (`@login_required`) + **RBAC**. | **Low** |
| **SEC-02** | **Broken Authentication & Missing Session Tokens** *(CWE-287)* | Boundary 1 | **Spoofing** & **Elevation of Privilege** | **T1078** (Valid Accounts) / **T1110** (Brute Force) | **HIGH** *(High × High)*: `POST /auth/login` returns only a raw `user_id` (`43`) with no cryptographic session token, MFA, or rate limiting against credential stuffing. | Issue signed session tokens, enforce **Flask-Limiter** & **Fail2Ban** IP throttling, integrate **MFA** or **WebAuthn Passkeys**, and upgrade hashing to **Argon2id** (NIST SP 800-63B). | **Low** |
| **SEC-03** | **Security Misconfiguration: Active Debugger & Raw Tracebacks** *(CWE-200)* | Boundary 2 | **Information Disclosure** & **Elevation of Privilege** | **T1082** (System Info Discovery) / **T1059.006** (Python Execution) | **HIGH** *(Medium × Critical)*: Running `debug=True` exposes the Werkzeug interactive **Debugger PIN (`120-454-171`)** enabling Remote Code Execution (RCE), while `details: str(e)` leaks internal stack traces on malformed JSON. | Disable debug mode in production, implement sanitised global `@app.errorhandler(500)` JSON responses, and capture exceptions securely via **Sentry**. | **Low** |
| **SEC-04** | **Hardcoded Secrets & Unencrypted Transport** | Boundary 1 & 2 | **Information Disclosure** & **Spoofing** | **T1552.001** (Credentials in Files) / **T1557** (Adversary-in-the-Middle) | **HIGH** *(Medium × High)*: Plaintext `GOOGLE_BOOKS_API_KEY` and MySQL credentials in `config.py` risk repo exposure; HTTP cleartext transmission exposes PII and login passwords to sniffing. | Migrate secrets to OS environment variables, enforce **TLS 1.3** via an **Nginx** reverse proxy + **Flask-Talisman** (`force_https=True`, HSTS), and require **TLS 1.2+** for MySQL connections. | **Low** |
| **SEC-05** | **Stored XSS, Homograph & SQL `LIMIT` Risks** *(CWE-79 / CWE-89)* | Boundary 3 & 4 | **Tampering** | **T1059.007** (JavaScript Execution) / **T1036.008** (Masquerading) | **MEDIUM** *(Medium × Medium)*: API accepts raw `<script>alert(1)</script>` payloads in book reviews (`POST /users/42/books/1/reviews/add_review`); `LIMIT` clauses use f-strings wrapped in `int()`; lack of negative access tests on DB. | Enforce strict schema validation via **Pydantic**, apply Unicode **NFKC** normalisation in `models.py`, migrate to **SQLAlchemy ORM**, and restrict MySQL accounts to **DML-only** and read-only **SQL Views** (PoLP). | **Very Low** |
| **SEC-06** | **Security Logging & Supply Chain Gaps** | Boundary 2 & 4 | **Repudiation** & **Elevation of Privilege** | **T1070** (Indicator Removal) / **T1195** (Supply Chain Compromise) | **MEDIUM** *(Medium × Medium)*: Ephemeral `print(f"CRITICAL ERROR: {e}")` statements leave no audit trail for forensic investigation; unmonitored third-party Python packages risk known vulnerability exploitation. | Replace `print()` with Python's `logging` module (excluding plaintext passwords) feeding into an **ELK Stack SIEM** and **Grafana**, and automate dependency scanning via **`pip-audit`** and **GitHub Dependabot**. | **Low** |

---

## 4. Key Technical Evidence & Remediation Architecture

### 4.1 Fixing Broken Object Level Authorisation (SEC-01 & SEC-02)
* **Burp Suite Proof of Concept:** Two test accounts were registered—**Alice (`user_id: 42`)** and **Bob (`user_id: 43`)**. Sending an unauthenticated `POST /users/43/library/add_book` request directly modified Bob's personal library, proving the API blindly trusts the URL parameter. Furthermore, `POST /auth/login` returned `"status": "success"` and `"user_id": 43` in the body with zero session headers.
* **Vulnerable Design Pattern (`app.py`):** Endpoints rely directly on client-supplied URL path parameters (`PUT /users/<user_id>/library/<book_id>` or `GET /user/<int:user_id>/library`) without validating whether the requester owns that identity.
* **Secure Re-Architecture:** Eliminate client-supplied `user_id` parameters from routes entirely by shifting to contextual endpoints (`/user/library` or `/api/v1/me/library`) protected by `@login_required` via **Flask-Login** or decoded stateless **JWTs** stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookies. User identity is extracted strictly from the server-verified token or session prior to executing `db_utils.insert_book(current_user.id, book_id)`, paired with **Role-Based Access Control (RBAC)** and **Pydantic** payload validation.

### 4.2 Hardening Transport, Error Handling & Secrets Management (SEC-03 & SEC-04)
* **Burp Suite Proof of Concept:** Sending malformed JSON to `POST /users/42/books/1/reviews/add_review` triggered raw Werkzeug exception tracebacks, while local execution with `debug=True` exposed an active `Debugger PIN: 120-454-171` in the terminal. Additionally, static review of `config.py` revealed hardcoded placeholders for `GOOGLE_BOOKS_API_KEY` and MySQL credentials.
* **Secure Re-Architecture:**
  1. **Transport Encryption:** Deploy the Flask application behind an **Nginx** or **Apache** reverse proxy performing **TLS 1.3** termination, and wrap the application in **Flask-Talisman** (`Talisman(app, force_https=True)`) to enforce **Strict-Transport-Security (HSTS)** headers and prevent HTTP downgrade or Man-in-the-Middle (MitM) attacks. Verify encrypted traffic using **Wireshark** and **OWASP ZAP**.
  2. **Runtime & Error Sanitisation:** Set `debug=False` in production to disable the Werkzeug interactive debugger. Intercept `500 Internal Server Error` exceptions via `@app.errorhandler(500)` in `app.py` to return generic JSON messages to the client while routing full stack traces internally to **Sentry** and structured log files via `logger.error()` rather than exposing `'details': str(e)`.
  3. **Secrets & Rate Limiting:** Move `GOOGLE_BOOKS_API_KEY` and MySQL connection parameters out of `config.py` into OS environment variables (`os.environ.get()`), and apply **Flask-Limiter** alongside **Fail2Ban** to throttle repeated login attempts.

---

## 5. Defense-in-Depth Remediation Roadmap

### Identity, Authentication & Access Control
- [x] Verify baseline password hashing (`scrypt` via Werkzeug 3.1.8) and regex complexity policies.
- [ ] Re-architect endpoints to contextual routes (`/user/library`) with **Flask-Login** (`@login_required`) or stateless **JWTs** encapsulated in `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
- [ ] Enforce **Role-Based Access Control (RBAC)** and negative integration testing across all authorisation boundaries.
- [ ] Implement login throttling via **Flask-Limiter** and host-level IP banning with **Fail2Ban**.
- [ ] Upgrade password hashing to **Argon2id**, remove maximum password length caps per **NIST SP 800-63B**, and evaluate **MFA** or **WebAuthn Passkeys**.

### Data Layer, Input Validation & Transport Security
- [x] Audit SQL parameterisation (`%s` tuple placeholders), socket-closing context managers in `db_connection.py`, and `localhost` port `3306` binding.
- [ ] Migrate data access to **SQLAlchemy ORM** to eliminate `LIMIT` f-string patterns entirely.
- [ ] Enforce the **Principle of Least Privilege (PoLP)** on MySQL: restrict the API service account strictly to **DML** operations (denying **DDL** schema changes) and abstract queries via read-only **SQL Views**.
- [ ] Enforce **Pydantic** payload validation and Unicode **NFKC** normalisation in `models.py` to prevent Stored XSS (`CWE-79`) and homograph attacks.
- [ ] Deploy behind an **Nginx** reverse proxy with **TLS 1.3**, **Flask-Talisman** (`force_https=True`), and encrypted **TLS 1.2+** MySQL connections.
- [ ] Remove hardcoded credentials from `config.py` (`GOOGLE_BOOKS_API_KEY`, MySQL credentials) and migrate to environment variables.

### SecOps, Logging & Supply Chain Governance
- [ ] Replace `print()` debugging with Python's `logging` module (NIST SP 800-92 compliant, redacting sensitive PII and `/auth/register` passwords).
- [ ] Centralise logs and error tracking into an **ELK Stack SIEM**, **Sentry**, and **Grafana** anomaly dashboards.
- [ ] Integrate **`pip-audit`** and **GitHub Dependabot** into the workflow for automated vulnerability scanning and patch management.