"""Research metadata and bounded reproduction inputs, all fictional."""
from lab.scenarios import jwt_token

DATA = [
('idor', 'Invoice ownership bypass', '639', 'API1:2023', 'access-control', '/api/invoices', {'id':'2'}, {'id':'1'}, 'Missing per-object ownership authorization after authentication.', 'Read another fictional user invoice.', 'invoice', 'Fixture tokens stand in for a real identity provider.'),
('sql', 'SQL predicate injection', '89', 'A03:2021', 'sql-injection', '/sql', {'q':"' OR 1=1 --"}, {'q':'Alice'}, 'String concatenation lets input change the SQL predicate.', 'Read Bob private note from an in-memory database.', 'sql', 'SQLite in-memory SELECT only; no persistence or stacked statement execution.'),
('xss', 'Reflected HTML script execution', '79', 'A03:2021', 'cross-site-scripting', '/xss', {'q':'<script>window.__bp=1</script>'}, {'q':'hello'}, 'Unescaped input is inserted into an HTML body context.', 'Execute a marker script in the local fixture origin.', 'xss', 'HTML body context only; no cookie theft or external callbacks.'),
('ssrf', 'Internal service request exposure', '918', 'API7:2023', 'ssrf', '/ssrf', {'url':'http://127.0.0.1:8093/private'}, {'url':'http://127.0.0.1:8093/public'}, 'User-selected destination is fetched without application authorization.', 'Read a fictional internal marker through the application.', 'ssrf', 'Transport is caged to two exact loopback URLs; DNS rebinding and external egress are excluded.'),
('jwt', 'Decode-only JWT authentication', '347', 'API2:2023', 'jwt', '/jwt', {}, {}, 'Claims are decoded without validating signature, algorithm, audience or expiry.', 'Impersonate the fictional Bob identity.', 'jwt', 'Fixed HS256 verifier is educational; use a maintained JOSE library in production.'),
('oauth', 'Account linking without session-bound state', '352', 'A07:2021', 'oauth', '/oauth/callback', {'state':'attacker-state'}, {}, 'Callback ignores state binding and permits unsolicited account linking.', 'Link the wrong fictional provider account.', 'oauth', 'Provider and code exchange are mocked; state lifecycle is real. PKCE and real provider integration are excluded.'),
('auth', 'Session fixation at login', '384', 'A07:2021', 'authentication', '/auth/login', {'password':'fictional-alice-password'}, {}, 'Successful login promotes the caller-selected session identifier.', 'Reuse the known session identifier after victim login.', 'auth', 'Fictional password is public; no credential guessing. Cookies omit Secure for loopback HTTP only.'),
('path', 'Document path escapes public root', '22', 'A01:2021', 'file-path-traversal', '/path', {'name':'../private/marker.txt'}, {'name':'hello.txt'}, 'Filesystem path is joined without checking the resolved containment boundary.', 'Read a fictional private marker outside the public directory.', 'path', 'Outer allowlist limits the reachable files to two fixture files.'),
('command', 'Shell command separator injection', '78', 'A03:2021', 'os-command-injection', '/command', {'value':'hello; printf INJECTED'}, {'value':'hello'}, 'User input is interpolated into a shell command string.', 'Execute a second harmless printf command.', 'command', 'Only two exact payloads are accepted. No arbitrary commands, networking or filesystem writes.'),
('business', 'Client-controlled role escalation', '915', 'API3:2023', 'logic-flaws', '/business', {'role':'admin'}, {'role':'reader'}, 'A client-controlled role is trusted during a profile update.', 'Escalate to administrator and read the fictional admin-only audit marker.', 'business', 'Roles persist only in process memory; the protected administrator resource is a fictional marker. Restart resets roles.')]


def catalog():
    result = []
    for number, row in enumerate(DATA, 1):
        slug,title,cwe,owasp,topic,path,attack,legit,cause,impact,source,limit = row
        result.append(dict(id=f'BP-{number:03}', slug=slug, title=title, cwe='CWE-'+cwe,
                           owasp=owasp, severity='High', path=path, attack=attack, legitimate=legit,
                           rootCause=cause, impact=impact, source=source, limitation=limit,
                           reference='https://portswigger.net/web-security/'+topic,
                           labs='https://portswigger.net/web-security/all-labs'))
    return result
