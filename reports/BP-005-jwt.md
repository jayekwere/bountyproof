# BP-005: Decode-only JWT authentication

Educational local fixture finding. Severity: High. CWE-347; API2:2023.

Evidence collected: 2026-10-31T20:58:39.639313+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
Claims are decoded without validating signature, algorithm, audience or expiry.

## Impact
Impersonate the fictional Bob identity.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /jwt?token=eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYm9iIiwgImlzcyI6ICJib3VudHlwcm9vZiIsICJhdWQiOiAibG9jYWwtbGFiIiwgImV4cCI6IDE3OTM0ODA5MTl9. HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 20:58:39 GMT
Content-Type: application/json
Content-Length: 18
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"subject": "bob"}
```

## Remediation evidence
```http
GET /jwt?token=eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYm9iIiwgImlzcyI6ICJib3VudHlwcm9vZiIsICJhdWQiOiAibG9jYWwtbGFiIiwgImV4cCI6IDE3OTM0ODA5MTl9. HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 401
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 20:58:39 GMT
Content-Type: application/json
Content-Length: 26
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"error": "Invalid token"}
```

## Legitimate operation
```http
GET /jwt?token=eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiYWxpY2UiLCAiaXNzIjogImJvdW50eXByb29mIiwgImF1ZCI6ICJsb2NhbC1sYWIiLCAiZXhwIjogMTc5MzQ4MDkxOX0.VEWjRMYjnqZHjzLcKNL-ZipQw92t8u66eB8Cd9E_bmk HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 20:58:39 GMT
Content-Type: application/json
Content-Length: 20
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"subject": "alice"}
```

## Vulnerable code
```python
def jwt_vulnerable(token):
    # Decode-only verification mistake.
    return decode_part(token.split('.')[1])['sub']
```

## Corrected code
```python
def jwt_fixed(token):
    head, body, signature = token.split('.')
    header, claims = decode_part(head), decode_part(body)
    expected = b64(hmac.digest(JWT_KEY, (head + '.' + body).encode(), 'sha256'))
    if (header.get('alg') != 'HS256' or not hmac.compare_digest(signature, expected)
            or claims.get('iss') != 'bountyproof' or claims.get('aud') != 'local-lab'
            or type(claims.get('exp')) is not int or claims['exp'] <= time.time()
            or claims.get('sub') not in ('alice', 'bob')):
        raise ValueError('Invalid token')
    return claims['sub']
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Fixed HS256 verifier is educational; use a maintained JOSE library in production.

## Learning references
https://portswigger.net/web-security/jwt

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
