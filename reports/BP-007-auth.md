# BP-007: Session fixation at login

Educational local fixture finding. Severity: High. CWE-384; A07:2021.

Evidence collected: 2026-10-31T21:01:19.665465+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
Successful login promotes the caller-selected session identifier.

## Impact
Reuse the known session identifier after victim login.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /auth/login?password=fictional-alice-password HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice
Cookie: sid=known-session

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 17
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'
Set-Cookie: sid=known-session; HttpOnly; SameSite=Strict; Path=/

{"user": "alice"}
```

## Remediation evidence
```http
GET /auth/login?password=fictional-alice-password HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice
Cookie: sid=known-session

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 17
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'
Set-Cookie: sid=IP3H0erlLoVTMnljxDafCTMG2SWUcyUJ-H2mbEHnL0Q; HttpOnly; SameSite=Strict; Path=/

{"user": "alice"}
```

## Legitimate operation
```http
GET /auth/me HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice
Cookie: sid=IP3H0erlLoVTMnljxDafCTMG2SWUcyUJ-H2mbEHnL0Q

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 17
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"user": "alice"}
```

## Vulnerable code
```python
def auth_vulnerable(password, sid, sessions):
    if not hmac.compare_digest(password, PASSWORD):
        return 401, {'error': 'Bad credentials'}, None
    sessions[sid] = 'alice'
    return 200, {'user': 'alice'}, sid
```

## Corrected code
```python
def auth_fixed(password, sid, sessions):
    if not hmac.compare_digest(password, PASSWORD):
        return 401, {'error': 'Bad credentials'}, None
    sessions.pop(sid, None)
    fresh = secrets.token_urlsafe(32)
    sessions[fresh] = 'alice'
    return 200, {'user': 'alice'}, fresh
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Fictional password is public; no credential guessing. Cookies omit Secure for loopback HTTP only.

## Learning references
https://portswigger.net/web-security/authentication

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
