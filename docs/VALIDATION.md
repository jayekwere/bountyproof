# Validation evidence and limitations

The checked-in evidence records actual executions against owned fictional fixtures. It is not a third-party assessment, bounty result, Academy completion record or signed attestation. Collection timestamps and the exact scenario source SHA-256 are included in `evidence/results.json` and `evidence/docker-http.json`.

## Local checks

- `npm run verify`: TypeScript strict typecheck/build, two Node boundary tests and fifteen Python tests. The Python suite includes all ten HTTP lifecycles, missing authentication, malformed JWTs, wrong issuer/audience/expiry/signature, OAuth wrong-session/expired/reused state, state/session capacity, cage escape attempts, Host/Origin denial and resolved path containment.
- `npm run evidence`: ten real HTTP reproductions, ten corrected behavior checks, ten legitimate operations plus additional IDOR/session/OAuth evidence. `reports/` contains the generated per-finding reports.
- `npm run test:browser`: Chromium checks management authorization, cross-origin and write denial, XSS execution before and after remediation, all ten dashboard records, code/root-cause views, filtering, report downloads, empty browser storage, mobile overflow, JavaScript errors, desktop/mobile screenshots and TypeScript replay over HTTP.
- `python3 -m tools.sast --semgrep .scanner/bin/semgrep`: hash-locked Semgrep package 1.183.0. Its scanner JSON reports engine version 1.166.0. Three expected vulnerable sinks were found in the reviewed functions. Missing controls, scanner errors or findings outside the reviewed function boundaries fail the gate. See `evidence/semgrep.json`.
- `npm audit --audit-level=high`: no reported npm vulnerabilities at collection. See `evidence/npm-audit.json`. This does not audit the OS or prove future advisory absence.
- Docker builds completed with digest-pinned Node/Python images. All ten lifecycles passed through published loopback gateways. Six containers were inspected for non-root UID, read-only root, dropped capabilities, no new privileges, CPU/memory/PID controls, and loopback-only publishing. Lab routes contain no default route. See `evidence/docker-http.json`.

`evidence/verification.txt` records native test execution. `evidence/browser-results.json` records Playwright results. Screenshots are actual browser captures, not mockups. Hosted CI results are available only after a real workflow execution and should be verified at the repository's Actions page rather than inferred from a badge.

## What the tests do not establish

HTTP success alone is not exploit proof. SQL tests check disclosure of Bob's row and its absence afterward; command tests check whether the second printf executed; XSS tests execute a browser marker; session tests replay the old cookie; OAuth tests consume and retry state. Denied status codes are supplemented by legitimate positive controls. These assertions apply to the tested fixture variants only.

The SQL database is in memory. The OAuth provider exchange is mocked. JWT validation is a small educational implementation. Business roles persist in process memory and gate a fictional administrator-only audit resource. Session management uses fictional shared credentials, bounded in-memory state and no production idle-expiry/logout implementation. XSS covers HTML body reflection only. SSRF, path and command scenarios have immutable outer cages, so arbitrary egress, arbitrary files and arbitrary commands are deliberately unavailable. Native runs inherit the user's operating-system privileges. Docker limits and lack of routes are defense in depth, not a hostile code execution sandbox.

The SAST rules are narrow syntax checks rather than whole-program taint analysis. No DAST crawler, public scanner, brute-force utility, browser credential capture or unattended exploit API is included. No PortSwigger labs have been completed by these tests. Manual Burp procedures are documented but no unperformed Burp session is claimed. Chrome and Linux CI can differ from local Chromium/macOS; hosted CI is the cross-platform check.
