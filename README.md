# MarketGuard AppSec Lab

An exploit-to-remediation application security lab with two versions of the same marketplace service:

- **Vulnerable mode** demonstrates realistic web-security trust failures.
- **Secure mode** implements server-side remediation and regression controls.

The project is an original, local-only security lab. It contains no course flags, university identifiers, proprietary source code, production credentials, or third-party targets.

## What this demonstrates

| Module | Vulnerable behavior | Hardened control | Security theme |
|---|---|---|---|
| Search | User input rendered directly into HTML | Context-aware HTML escaping | Reflected XSS / injection |
| Reviews | Stored review body rendered as trusted markup | Encode stored untrusted content at output | Stored XSS |
| Account | State-changing POST requires no request-integrity proof | Session-bound CSRF token + SameSite session | CSRF |
| Admin | `role=admin` browser cookie grants authority | Signed session + server-side role lookup | Broken access control |
| Admin API | Sensitive data returned with permissive CORS | Authorization + origin allowlist | Security misconfiguration |
| Rewards | Negative redemption increases a user's balance | Positive-value invariant + balance validation | Business-logic abuse / insecure design |

## Why the repo is structured this way

A complete application-security exercise should show more than exploit payloads. Each issue here has five artifacts:

1. Reproducible vulnerable behavior.
2. Business/security impact.
3. Root-cause explanation.
4. Hardened implementation.
5. Regression test that prevents the flaw from returning.

This links concrete exploit behavior to root cause, remediation, and regression coverage.

## Quick start

### Option 1: Docker Compose

```bash
docker compose up --build -d
```

Open:

- Vulnerable: http://127.0.0.1:5000
- Secure: http://127.0.0.1:5001

Stop the lab:

```bash
docker compose down
```

### Option 2: Python only

The runtime uses only the Python 3.12 standard library.

Terminal 1:

```bash
LAB_MODE=vulnerable PORT=5000 python -m app.main
```

Terminal 2:

```bash
LAB_MODE=secure APP_SECRET=replace-me PORT=5001 python -m app.main
```

## Run the tests

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

The regression suite intentionally asserts both sides of each control: the vulnerable mode exhibits the flaw and the secure mode rejects or safely renders the same input.

## Local exploit demonstrations

After both services are running:

```bash
python exploits/xss_check.py
python exploits/access_control.py
python exploits/cors_check.py
python exploits/rewards_logic.py
```

The scripts refuse non-local hosts. See [`exploits/README.md`](exploits/README.md).

## Security pipeline

GitHub Actions includes:

- Python compilation and security regression tests.
- **SAST:** Bandit scan of hardened security helpers, plus an informational full-lab report because vulnerable mode intentionally contains insecure patterns.
- **DAST:** black-box HTTP checks against the running hardened service for XSS, broken access control, CORS exposure, CSRF, and negative reward redemption.

See [`.github/workflows/security.yml`](.github/workflows/security.yml).

## Threat model and risk documentation

- [`docs/threat-model.md`](docs/threat-model.md) — trust boundaries, assets, abuse cases, Mermaid DFD.
- [`docs/risk-register.md`](docs/risk-register.md) — likelihood, impact, OWASP mapping, remediation.
- [`docs/remediation-notes.md`](docs/remediation-notes.md) — engineering explanation for each fix.
- [`docs/secure-sdlc.md`](docs/secure-sdlc.md) — exploit-to-regression workflow.
- [`docs/architecture.md`](docs/architecture.md) — runtime and deployment design.

## Repository layout

```text
marketguard-appsec-lab/
├── app/
│   ├── main.py                 # vulnerable + secure HTTP service
│   ├── security.py             # signed session, CSRF, escaping helpers
│   └── state.py                # deterministic local demo data
├── exploits/                   # localhost-only demonstrations
├── tests/
│   ├── test_security_regressions.py
│   ├── test_secure_controls.py
│   └── dast_http.py            # black-box hardened-service checks
├── docs/
│   ├── architecture.md
│   ├── remediation-notes.md
│   ├── risk-register.md
│   ├── secure-sdlc.md
│   ├── threat-model.md
├── .github/workflows/
│   ├── test.yml
│   └── security.yml
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── SECURITY.md
└── LICENSE
```

## Design notes

The application deliberately avoids a web framework so the security decisions are visible in a compact codebase. That is not a recommendation to build production web applications from raw WSGI. In a production system, a mature framework should supply secure defaults, session management, CSRF integrations, templating, and middleware.

## Safe use

The vulnerable service is for local education only. Docker Compose binds it to loopback (`127.0.0.1`) so it is not exposed on all network interfaces. Do not remove that restriction on an untrusted network.

## License

MIT. See [`LICENSE`](LICENSE).
