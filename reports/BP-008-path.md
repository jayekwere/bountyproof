# BP-008: Document path escapes public root

Educational local fixture finding. Severity: High. CWE-22; A01:2021.

Evidence collected: 2026-10-31T21:03:54.576611+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
Filesystem path is joined without checking the resolved containment boundary.

## Impact
Read a fictional private marker outside the public directory.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /path?name=..%2Fprivate%2Fmarker.txt HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 41
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"content": "FICTIONAL_PRIVATE_MARKER\n"}
```

## Remediation evidence
```http
GET /path?name=..%2Fprivate%2Fmarker.txt HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 403
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 37
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"error": "Path escapes public root"}
```

## Legitimate operation
```http
GET /path?name=hello.txt HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 40
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"content": "Public fixture document\n"}
```

## Vulnerable code
```python
def path_vulnerable(name):
    return (ROOT / 'public' / name).read_text()
```

## Corrected code
```python
def path_fixed(name):
    target = (ROOT / 'public' / name).resolve()
    if not target.is_relative_to((ROOT / 'public').resolve()):
        raise PermissionError('Path escapes public root')
    return target.read_text()
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Outer allowlist limits the reachable files to two fixture files.

## Learning references
https://portswigger.net/web-security/file-path-traversal

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
