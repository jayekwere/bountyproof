# BP-009: Shell command separator injection

Educational local fixture finding. Severity: High. CWE-78; A03:2021.

Evidence collected: 2026-10-31T21:01:19.665465+00:00

## Scope
Owned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.

## Root cause
User input is interpolated into a shell command string.

## Impact
Execute a second harmless printf command.

## Reproduction
Start `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.

## Vulnerable evidence
```http
GET /command?value=hello%3B+printf+INJECTED HTTP/1.1
Host: 127.0.0.1:8091
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 27
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"output": "helloINJECTED"}
```

## Remediation evidence
```http
GET /command?value=hello%3B+printf+INJECTED HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 36
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"output": "hello; printf INJECTED"}
```

## Legitimate operation
```http
GET /command?value=hello HTTP/1.1
Host: 127.0.0.1:8092
Authorization: Bearer fixture-alice

HTTP/1.1 200
Server: BaseHTTP/0.6 Python/3.14.6
Date: Sat, 31 Oct 2026 21:01:19 GMT
Content-Type: application/json
Content-Length: 19
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'

{"output": "hello"}
```

## Vulnerable code
```python
def command_vulnerable(value):
    return subprocess.run('printf %s ' + value, shell=True, capture_output=True,
                          text=True, timeout=1, check=True).stdout
```

## Corrected code
```python
def command_fixed(value):
    return subprocess.run(['printf', '%s', value], shell=False, capture_output=True,
                          text=True, timeout=1, check=True).stdout
```

## Regression result
Reproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.

## Limitations
Only two exact payloads are accepted. No arbitrary commands, networking or filesystem writes.

## Learning references
https://portswigger.net/web-security/os-command-injection

https://portswigger.net/web-security/all-labs

No PortSwigger lab completion claimed.
