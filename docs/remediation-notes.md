# Remediation Notes

## XSS

The vulnerable mode places user-controlled strings directly into HTML. The hardened mode calls `html.escape(..., quote=True)` at the output boundary. The rule is contextual output encoding, not blacklist-based filtering.

## CSRF

The vulnerable account endpoint accepts a state-changing POST with no request-integrity proof. Hardened mode derives a CSRF token from the signed session and validates it using constant-time comparison. The session cookie is also `SameSite=Strict` and `HttpOnly`.

## Broken access control

Vulnerable mode trusts the browser's `role=admin` cookie. Hardened mode signs the session and resolves the user's role from server-controlled state before authorizing `/admin` or reward-management operations.

## CORS

Vulnerable mode returns `Access-Control-Allow-Origin: *` on an administrative user endpoint. Hardened mode requires authorization and only reflects an explicitly allowed local origin.

## Business logic

The vulnerable redemption endpoint computes `points -= amount` without validating the sign, so a negative redemption increases the balance. Hardened mode requires a positive integer and prevents redemption greater than the current balance.
