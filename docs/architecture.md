# Architecture

The repository intentionally keeps runtime dependencies at zero. The application is a small WSGI service built on Python's standard library so the security decisions remain visible instead of being hidden behind framework defaults.

Two deployment modes share the same route surface:

- `vulnerable`: demonstrates insecure trust decisions.
- `secure`: applies server-side validation, signed sessions, CSRF protection, output encoding, and restrictive authorization/origin checks.

Docker Compose binds both services to loopback only:

- `127.0.0.1:5000` — vulnerable
- `127.0.0.1:5001` — secure

The vulnerable service should never be exposed to a public interface.
