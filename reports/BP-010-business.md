# BP-010: Client-controlled role escalation

Educational local fixture finding. Severity: High. CWE-915; API3:2023.

Evidence collected: 2026-10-31T20:58:39.639313+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
A client-controlled role is trusted during a profile update.

## Impact
Escalate the fictional user role to admin in the response.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /business?role=admin HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 20:58:39 GMT
Content-Type: application/json
Content-Length: 34
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"user": "alice", "role": "admin"}
```

## Remediation evidence
```http
GET /business?role=admin HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 403
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 20:58:39 GMT
Content-Type: application/json
Content-Length: 61
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"error": "Role changes require administrator authorization"}
```

## Legitimate operation
```http
GET /business?role=reader HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 20:58:39 GMT
Content-Type: application/json
Content-Length: 35
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"user": "alice", "role": "reader"}
```

## Vulnerable code
```python
def business_vulnerable(role):
    return 200, {'user': 'alice', 'role': role}
```

## Corrected code
```python
def business_fixed(role):
    if role != 'reader':
        return 403, {'error': 'Role changes require administrator authorization'}
    return 200, {'user': 'alice', 'role': 'reader'}
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Request-local profile only; no persistent administrator capabilities.

## Learning references
https://portswigger.net/web-security/logic-flaws

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
