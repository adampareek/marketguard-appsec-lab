# Secure SDLC Workflow

Each lab module follows the same engineering loop:

1. Define the asset and trust boundary.
2. Reproduce the insecure behavior in vulnerable mode.
3. Record business and technical impact.
4. Identify the root-cause trust decision.
5. Implement a server-side remediation in secure mode.
6. Add a regression test that demonstrates vulnerable vs. secure behavior.
7. Run automated tests in CI and perform SAST/DAST checks against the hardened service.

This structure is deliberate: the lab demonstrates remediation and prevention, not only exploitation.
