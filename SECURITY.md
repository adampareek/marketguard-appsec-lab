# Security Policy

MarketGuard intentionally contains vulnerable code for local education and demonstration.

- Do not deploy the vulnerable service to the public internet.
- Docker Compose binds vulnerable mode to `127.0.0.1` by design.
- Exploit demos contain a host guard and refuse non-local targets.
- No real credentials, personal data, production secrets, or third-party targets are included.

If you find an unintended vulnerability in the hardened mode, open a private security report rather than publishing an exploit against a live deployment.
