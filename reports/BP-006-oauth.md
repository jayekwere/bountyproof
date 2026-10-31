# BP-006: Account linking without session-bound state

Educational local fixture finding. Severity: High. CWE-352; A07:2021.

Evidence collected: 2026-10-31T21:03:54.576611+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
Callback ignores state binding and permits unsolicited account linking.

## Impact
Link the wrong fictional provider account.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /oauth/callback?state=attacker-state HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 44
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"linked_account": "fictional-provider-bob"}
```

## Remediation evidence
```http
GET /oauth/callback?state=attacker-state HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 403
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 67
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"error": "State missing, expired, reused or not bound to session"}
```

## Legitimate operation
```http
GET /oauth/callback?state=lZFuAXVA_f-EIap-oInLEBM8Pqg3_AKm HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice
Cookie: sid=fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 44
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"linked_account": "fictional-provider-bob"}
```

## Additional regression evidence 1
```http
GET /oauth/callback?state=lZFuAXVA_f-EIap-oInLEBM8Pqg3_AKm HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice
Cookie: sid=fixture-alice

HTTP/1.1 403
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 67
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"error": "State missing, expired, reused or not bound to session"}
```

## Vulnerable code
```python
def oauth_vulnerable(state, cookie, states):
    return 200, {'linked_account': 'fictional-provider-bob'}
```

## Corrected code
```python
def oauth_fixed(state, cookie, states):
    entry = states.get(state)
    if not entry or entry[0] != cookie or entry[1] < time.monotonic():
        return 403, {'error': 'State missing, expired, reused or not bound to session'}
    del states[state]
    return 200, {'linked_account': 'fictional-provider-bob'}
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Provider and code exchange are mocked; state lifecycle is real. PKCE and real provider integration are excluded.

## Learning references
https://portswigger.net/web-security/oauth

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
