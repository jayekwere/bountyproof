# BP-004: Internal service request exposure

Educational local fixture finding. Severity: High. CWE-918; API7:2023.

Evidence collected: 2026-10-31T21:01:19.665465+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
User-selected destination is fetched without application authorization.

## Impact
Read a fictional internal marker through the application.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /ssrf?url=http%3A%2F%2F127.0.0.1%3A8093%2Fprivate HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 40
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"content": "FICTIONAL_INTERNAL_MARKER"}
```

## Remediation evidence
```http
GET /ssrf?url=http%3A%2F%2F127.0.0.1%3A8093%2Fprivate HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 403
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 40
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"error": "Destination is not approved"}
```

## Legitimate operation
```http
GET /ssrf?url=http%3A%2F%2F127.0.0.1%3A8093%2Fpublic HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 30
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"content": "Public stock: 7"}
```

## Vulnerable code
```python
def ssrf_vulnerable(url):
    return fixture_fetch(url)
```

## Corrected code
```python
def ssrf_fixed(url):
    if url != 'http://127.0.0.1:8093/public':
        return 403, {'error': 'Destination is not approved'}
    return fixture_fetch(url)
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Transport is caged to two exact loopback URLs; DNS rebinding and external egress are excluded.

## Learning references
https://portswigger.net/web-security/ssrf

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
