# Contributing

Use fictional data and original code. Keep every exploit bounded to owned local fixtures. Do not add target URL flags, public scanning, credential attacks, account integrations, arbitrary shell payloads or automatic external exploitation.

Every scenario needs vulnerable and corrected implementations, real HTTP reproduction evidence, root cause, impact, CWE, a versioned OWASP mapping, original research notes, positive and negative regression tests and explicit limitations. Browser claims need actual browser verification. Do not copy copyrighted training solutions or invent disclosures and completion claims.

Run `npm ci --ignore-scripts`, `npm run verify`, `npm run evidence`, `npm run test:browser`, the hash-locked Semgrep gate and `npm audit --audit-level=high`. Validate Docker changes with `docker compose --profile lab up -d --build --wait` and `python3 -m tools.docker_verify`, then tear down. Keep generated reports and screenshots consistent with source. Note that timestamps, ephemeral tokens and expiries make fresh evidence intentionally nondeterministic.

Do not silently widen expected SAST findings. A reviewed exception must name the exact vulnerable function and explain its outer cage. Preserve loopback exposure, internal backend networks, resource limits, read-only roots, non-root users and the no-deployment CI policy.
