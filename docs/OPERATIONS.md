# Operating the lab

## Installation and startup

Use Python 3.12+, Node 24.13+ or 26, and optionally Docker Engine 28+ with Compose supporting profiles and `--wait`. Install locked npm dependencies using `npm ci --ignore-scripts`; build with `npm run build`. Run commands from the repository root. No Python runtime packages are required. Scanner installation uses a separate virtual environment and a hash-locked requirements file.

Native: `npm start` starts only management on 127.0.0.1:8090. `npm run lab` starts vulnerable 8091, fixed 8092 and internal upstream 8093. It handles Ctrl-C and SIGTERM. Never leave the fixtures running unattended. Stop them before `npm run verify`, `npm run evidence` or browser tests; these suites own their listeners and fail closed on a port collision. Do not kill unrelated processes to make a port available.

Docker: `docker compose up -d --build --wait` starts management only. Get its ephemeral token with `docker compose logs dashboard`. Enable fixtures with `docker compose --profile lab up -d --build --wait`. Run `python3 -m tools.docker_verify` for host replay and container security inspection. Teardown with `docker compose --profile lab down`. There are no named volumes or persisted user data. Do not use `network_mode: host`, add Docker socket mounts, relax cages, or remove loopback bindings. Internal networks are retained behind small fixed upstream gateways for compatibility with Docker's internal-network publishing behavior.

## Evidence refresh and reports

`npm run evidence` starts fresh owned native fixtures, captures HTTP traffic, asserts all ten malicious/positive cases and writes `evidence/results.json` plus `reports/BP-*.md`. This is a deliberate replacement of generated evidence. Dates, JWT expiries, OAuth state and session identifiers vary between runs. Historical JWTs in reports will expire; refresh evidence to obtain live replay inputs. TypeScript CLI uses the recorded attack parameters. To replay a current legitimate JWT, use the Python lifecycle suite instead of the historical token.

`npm run test:browser` requires installed Playwright Chromium and starts its own dashboard/labs. It exports desktop/mobile screenshots, browser results and report-download checks. No UI credentials are embedded in screenshots. The ephemeral management token is passed by an HTTP header and cleared after connection. Reload the page to disconnect. Restart the server to revoke every previous management token.

## Troubleshooting

- `Address already in use`: stop the BountyProof process or Compose project you started, then rerun. Do not point verification at an existing unknown listener.
- `401` on management: use the token from the currently running dashboard process. Docker logs may contain tokens from earlier restarts; use the most recent startup line.
- Gateway `502`: check backend health with `docker compose ps`. Only the selected profile's backends should be running.
- Missing browser: run `npx playwright install chromium`; Linux CI uses `--with-deps`.
- Semgrep certificate setup: on Homebrew systems ensure the OS trust store is available. Run the isolated scanner environment from the lockfile. Scanner failure is a failure, never an empty clean report.
- Missing evidence: run `npm run evidence` before starting the dashboard.

## Publishing restrictions

Publishing source code to GitHub is allowed. Public hosting of vulnerable listeners is prohibited. There is no public deployment workflow or Sites registration. The dashboard stays local because the requested product includes intentionally vulnerable runtime components. Documentation images and fictional evidence may be published as repository artifacts. Never add PortSwigger credentials, account cookies, employer data, real target URLs or private program material.
