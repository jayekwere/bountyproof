# BP-002: SQL predicate injection

Educational local fixture finding. Severity: High. CWE-89; A03:2021.

Evidence collected: 2026-10-31T21:03:54.576611+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
String concatenation lets input change the SQL predicate.

## Impact
Read Bob private note from an in-memory database.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /sql?q=%27+OR+1%3D1+-- HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 48
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"rows": [["Alice note"], ["Bob private note"]]}
```

## Remediation evidence
```http
GET /sql?q=%27+OR+1%3D1+-- HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 12
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"rows": []}
```

## Legitimate operation
```http
GET /sql?q=Alice HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:03:54 GMT
Content-Type: application/json
Content-Length: 26
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"rows": [["Alice note"]]}
```

## Vulnerable code
```python
def sql_vulnerable(q):
    with closing(sqlite3.connect(':memory:')) as db:
        db.executescript("CREATE TABLE notes(owner TEXT, body TEXT); INSERT INTO notes VALUES ('alice','Alice note'),('bob','Bob private note');")
        return db.execute("SELECT body FROM notes WHERE owner='alice' AND body LIKE '%" + q + "%'").fetchall()
```

## Corrected code
```python
def sql_fixed(q):
    with closing(sqlite3.connect(':memory:')) as db:
        db.executescript("CREATE TABLE notes(owner TEXT, body TEXT); INSERT INTO notes VALUES ('alice','Alice note'),('bob','Bob private note');")
        return db.execute("SELECT body FROM notes WHERE owner=? AND body LIKE ?", ('alice', '%' + q + '%')).fetchall()
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
SQLite in-memory SELECT only; no persistence or stacked statement execution.

## Learning references
https://portswigger.net/web-security/sql-injection

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
