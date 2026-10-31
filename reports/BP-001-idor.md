# BP-001: Invoice ownership bypass

Educational local fixture finding. Severity: High. CWE-639; API1:2023.

Evidence collected: 2026-10-31T21:03:54.576611+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
Missing per-object ownership authorization after authentication.

## Impact
Read another fictional user invoice.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /api/invoices?id=2 HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 30
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"owner": "bob", "total": 450}
```

## Remediation evidence
```http
GET /api/invoices?id=2 HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 403
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 22
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"error": "Forbidden"}
```

## Legitimate operation
```http
GET /api/invoices?id=1 HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 32
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"owner": "alice", "total": 120}
```

## Additional regression evidence 1
```http
GET /api/invoices?id=2 HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-bob

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 30
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"owner": "bob", "total": 450}
```

## Vulnerable code
```python
def invoice(identifier, session, mode):
    actor = SESSIONS.get(session)
    if not actor:
        return 401, {'error': 'Authentication required'}
    record = INVOICES.get(identifier)
    if not record:
        return 404, {'error': 'Not found'}
    if mode == 'fixed' and record['owner'] != actor:
        return 403, {'error': 'Forbidden'}
    return 200, record
```

## Corrected code
```python
def invoice(identifier, session, mode):
    actor = SESSIONS.get(session)
    if not actor:
        return 401, {'error': 'Authentication required'}
    record = INVOICES.get(identifier)
    if not record:
        return 404, {'error': 'Not found'}
    if mode == 'fixed' and record['owner'] != actor:
        return 403, {'error': 'Forbidden'}
    return 200, record
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Fixture tokens stand in for a real identity provider.

## Learning references
https://portswigger.net/web-security/access-control

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
