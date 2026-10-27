# Risk Register

| Risk | Vulnerability | Likelihood | Impact | OWASP mapping | Hardened control |
|---|---|---:|---:|---|---|
| R-01 | Reflected XSS in search results | High | Medium | A03: Injection | Context-aware HTML escaping |
| R-02 | Stored XSS in product reviews | High | High | A03: Injection | Encode untrusted stored content at output |
| R-03 | Cross-site request forgery on email changes | Medium | Medium | A01: Broken Access Control / request integrity | Session-bound CSRF token + SameSite cookie |
| R-04 | Admin authorization based on role cookie | High | Critical | A01: Broken Access Control | Signed session + server-side role lookup |
| R-05 | Sensitive admin API exposed by permissive CORS | Medium | High | A05: Security Misconfiguration | Allowlisted origin + authorization |
| R-06 | Negative reward redemption increases balances | High | High | A04: Insecure Design | Positive integer invariant + balance checks |

## Prioritization

R-04 is treated as highest priority because it converts a client-controlled string into administrative authority. R-06 follows because it violates a financial/business invariant and can be exploited without memory-corruption or injection primitives.
