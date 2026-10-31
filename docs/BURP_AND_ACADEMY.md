# Burp Community and Academy research workflow

Use official [PortSwigger Academy topics](https://portswigger.net/web-security/all-topics) and [public lab index](https://portswigger.net/web-security/all-labs) for learning. The ten finding reports link their relevant topic directly. This project contains original code and research notes, not copies of Academy solutions. No Academy lab completion is claimed or inferred from these local tests. No login, cookies, personal account details or paid Burp features are required.

## Manual IDOR investigation

1. Start the isolated fixture using `npm run lab` or the Docker `lab` profile. Scope Burp to `http://127.0.0.1:8091` and `http://127.0.0.1:8092` only. Keep automated crawling and extensions that contact external targets disabled.
2. Create a Repeater request to port 8091:

   ```http
   GET /api/invoices?id=1 HTTP/1.1
   Host: 127.0.0.1:8091
   Authorization: Bearer fixture-alice
   ```

3. Confirm 200 and Alice's invoice. Change only the identifier to `2`; confirm 200 and Bob's invoice. Record both raw requests and responses with timestamps.
4. Review `invoice` in `lab/scenarios.py`. Authentication maps the bearer to an actor; vulnerable mode omits the object ownership decision.
5. Replay the same `id=2` request against fixed port 8092, updating the Host header to match. Confirm 403. This route invokes the corrected server-side ownership condition.
6. On fixed port 8092, use `fixture-bob` with invoice 2 and `fixture-alice` with invoice 1. Confirm both return 200. Remove authentication and confirm 401. Request invoice 3 and confirm 404.
7. Run `npm run evidence` after stopping manual listeners. Compare the automated report with your own captures. Keep conclusions bounded to this fictional lab.

## Research notes for additional scenarios

SQL: compare the concatenated predicate with bound SQL parameters. The negative test checks absence of Bob's row, not just a successful status. XSS: HTTP escaping checks are supplemented by real Chromium execution of a harmless `window.__bp` marker. SSRF: distinguish the immutable transport cage from the application's public/private resource authorization rule. A cage-denied external URL is not a vulnerable destination test.

JWT: decode-only authentication accepts an unsigned Bob claim; the fixed validator pins HS256 and checks signature and registered claims. OAuth: test missing state, wrong-session state, expiry, successful callback and replay of consumed state. The provider exchange is mocked, so this is an account-link state boundary demonstration, not a complete OAuth integration audit.

Session: authenticate using a known session identifier, then replay the old cookie. It works in vulnerable mode and fails after fixed-mode rotation. Path: inspect resolution of a relative path before checking directory containment. Command: the only accepted attack appends a second harmless printf; no other shell commands are accepted. Business logic: user-controlled role assignment must be rejected using trusted server policy.

For actual Academy work, use only PortSwigger-provided lab instances under their rules. Record real completion evidence separately if you choose to do those labs. BountyProof tools intentionally cannot select those remote targets.
