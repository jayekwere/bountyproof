# BP-003: Reflected HTML script execution

Educational local fixture finding. Severity: High. CWE-79; A03:2021.

Evidence collected: 2026-10-31T21:03:54.576611+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
Unescaped input is inserted into an HTML body context.

## Impact
Execute a marker script in the local fixture origin.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /xss?q=%3Cscript%3Ewindow.__bp%3D1%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 80
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

<!doctype html><title>Search result</title><p><script>window.__bp=1</script></p>
```

## Remediation evidence
```http
GET /xss?q=%3Cscript%3Ewindow.__bp%3D1%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 92
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

<!doctype html><title>Search result</title><p>&lt;script&gt;window.__bp=1&lt;/script&gt;</p>
```

## Legitimate operation
```http
GET /xss?q=hello HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 55
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

<!doctype html><title>Search result</title><p>hello</p>
```

## Vulnerable code
```python
def xss_vulnerable(q):
    return '<!doctype html><title>Search result</title><p>' + q + '</p>'
```

## Corrected code
```python
def xss_fixed(q):
    return '<!doctype html><title>Search result</title><p>' + html.escape(q, quote=True) + '</p>'
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
HTML body context only; no cookie theft or external callbacks.

## Learning references
https://portswigger.net/web-security/cross-site-scripting

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
