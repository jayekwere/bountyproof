# Threat model

## Assets and scope

Assets are the workstation, management token, integrity of research evidence and isolation of the lab. All identities, passwords, JWT keys, provider identities, invoices and markers are fictional and public. The intended adversary is malicious fixture input or a hostile web origin trying to reach localhost. Host administrators, users controlling Docker and compromised OS/browser runtimes are outside the enforced boundary.

## Boundaries and controls

| Boundary | Threat | Control | Validation |
| --- | --- | --- | --- |
| Public network to workstation | Accidental public exposure | Loopback native binds and published ports; lab Compose profile opt-in | Docker port inspection; native code review |
| Browser to management API | Unauthorized reads, DNS rebinding, cross-site requests | Fresh 256-bit bearer token, exact Host checks, Origin and cross-site rejection, no CORS | Playwright negative requests |
| Management API to fixture execution | Dashboard becomes an exploit service | Read-only GET API; no process or target execution routes | Write request rejection; code review |
| Lab request to shell | Arbitrary command execution | Immutable exact payload cage, one-second timeout, dropped capabilities and limits | Negative command tests; Docker controls |
| Lab request to network | External SSRF and proxy escape | Exact URL cage, no redirects/proxies, private loopback upstream, no default route in lab containers | Malformed/external destination tests; route inspection |
| Lab request to filesystem | Host secret disclosure | Two-file cage, fixture-only image, no mounts, read-only root | Negative file tests; resolved containment checks |
| Gateway to backend | Arbitrary proxying | Immutable service/port map, relative request path only, three-second timeout | Docker replay and gateway code review |
| Artifact to browser DOM | Stored XSS from exploit evidence | `textContent`, no HTML insertion, restrictive CSP, no remote assets | Browser XSS isolation and UI tests |
| Dependency/CI boundary | Supply chain changes or privileged jobs | Lockfiles, digest-pinned images, commit-pinned actions, npm audit, read-only workflow | CI and reproducible Docker builds |
| OAuth/session state | Unbounded memory or stale state | 100 entry capacities, OAuth 60-second expiry, session ID rotation in fixed mode | State expiry/reuse tests; capacity tests |

## Residual risks

Native fixture processes run with the invoking user's privileges. Exact input cages are essential and must not be weakened. A future cage bypass or dependency flaw could threaten the workstation; prefer Docker or a disposable VM. Containers share the host kernel, so they are a containment layer, not a hostile multi-tenant execution boundary. Docker engine administrators can connect extra networks or publish new interfaces, bypassing these assumptions.

Gateways have regular ingress networks and thus potential egress if compromised. They contain no vulnerable fixture logic and forward only to their named backend. Internal services can communicate with their own gateway, which is why arbitrary URL execution remains prohibited even inside Docker. No internet requests are used as an isolation test.

The public fixture tokens are not management credentials. Authentication is simplified and unsuitable for production. Login uses GET to make manual lab replay straightforward; its password is fictional and must never be replaced with a real password. Fixed sessions have no production logout or idle expiry implementation and are capped until fixture restart. The management API uses HTTP on loopback and assumes a trusted host. Its token is visible to users who can read process logs and is not a multi-user tenancy mechanism.

Severity describes the uncaged application flaw; outer cages deliberately reduce actual lab impact. Reports do not claim internet exposure or real victim data. Historical evidence and tokens in reports are fictional or ephemeral local lab session values, not personal account information. No PortSwigger account is contacted.
